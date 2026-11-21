//! Consent-o-tron (http://localhost:4003).
//!
//! Producer: sign in with wallet → pick an agreement template → fill it in,
//! upload the file, name the person giving consent → sign the credential.
//! Cosigner: open the emailed link → review terms, agreement and file →
//! consent with their wallet → their wallet also signs the CAWG identity
//! assertion while Consent-o-tron authors the final file.
//!
//! Consent-o-tron also runs the status list (withdrawal) under its own
//! service key, and verifies any file on /verify.
//!
//! Records live in MongoDB (`agreements`, `sessions`, `challenges`,
//! `counters`, `outbox`); uploaded and signed files in the GCS bucket (or
//! data/blobs/ locally). The one thing kept in memory is the hand-off to
//! the cosigner's wallet while a file is being authored.

mod authoring;

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, Context as _};
use authoring::{IdentityRequest, WalletSigner};
use axum::{
    extract::{DefaultBodyLimit, Multipart, Path as UrlPath, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use cawg_consent_test::{
    add_proof, build_credential, build_status_list, did_key, did_of_vm, load_ed25519_pem, now, pki, resolve_did_key, sha256_b64,
    uuid_v4,
    verify::{verify_asset, Inputs, Report, TrqpQuery, TrqpQuestion},
    verify_cert_chain, verify_proofs, CredentialParams,
};
use demo_common::{
    esc,
    mongodb::{
        bson::{doc, Document},
        options::{FindOneAndUpdateOptions, ReturnDocument},
        Collection,
    },
    registry_authority, script_json, Blobs, Mailer, Site, CERT_SITE, CONSENT_SITE, REGISTRY_URL,
};
use ed25519_dalek::{Signature, SigningKey, Verifier};
use futures_util::TryStreamExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const SITE: Site = Site { class: "consent", name: "Consent-o-tron" };
const MAX_UPLOAD: usize = 25 * 1024 * 1024;

// ------------------------------------------------------------------ data

#[derive(Clone, Deserialize)]
struct Template {
    id: String,
    title: String,
    description: String,
    public: Vec<Field>,
    private: Vec<Field>,
    agreement: String,
    #[serde(rename = "credentialType")]
    credential_type: String,
    #[serde(rename = "schemaId")]
    schema_id: String,
}

#[derive(Clone, Deserialize)]
struct Field {
    name: String,
    label: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    options: Vec<String>,
    default: Value,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    AwaitingProducer,
    AwaitingCosigner,
    Authoring,
    Signed,
    Failed,
}

#[derive(Serialize, Deserialize)]
struct Agreement {
    #[serde(rename = "_id")]
    id: String,
    created_at: String,
    template_id: String,
    title: String,
    producer_did: String,
    producer_email: String,
    cosigner_email: String,
    invite_token: String,
    asset_name: String,
    /// Object key of the uploaded file.
    asset_key: String,
    asset_hash: String,
    /// The unsecured credential, as JSON text so it round-trips byte-exact.
    credential: String,
    /// `{ salt, agreement }`, kept by Consent-o-tron for the parties.
    private_agreement: String,
    agreement_text: String,
    producer_proof: Option<String>,
    participant_proof: Option<String>,
    cosigner_did: Option<String>,
    cosigner_chain_pem: Option<String>,
    status_index: i64,
    revoked: bool,
    stage: Stage,
    error: Option<String>,
    /// Object key of the signed file.
    signed_key: Option<String>,
}

impl Agreement {
    fn unsecured(&self) -> Value {
        serde_json::from_str(&self.credential).unwrap_or(Value::Null)
    }

    /// The credential with whatever proofs exist so far.
    fn credential_with_proofs(&self) -> Value {
        let mut credential = self.unsecured();
        let proofs: Vec<Value> = [&self.producer_proof, &self.participant_proof]
            .into_iter()
            .flatten()
            .filter_map(|p| serde_json::from_str(p).ok())
            .collect();
        if !proofs.is_empty() {
            credential["proof"] = Value::Array(proofs);
        }
        credential
    }

    fn public_terms(&self) -> Value {
        self.unsecured()["credentialSubject"]["consent"].clone()
    }
}

#[derive(Serialize, Deserialize)]
struct WebSession {
    #[serde(rename = "_id")]
    token: String,
    did: String,
    email: String,
}

#[derive(Serialize, Deserialize)]
struct Challenge {
    #[serde(rename = "_id")]
    value: String,
}

#[derive(Clone)]
struct App {
    root: PathBuf,
    templates: Arc<Vec<Template>>,
    agreements: Collection<Agreement>,
    sessions: Collection<WebSession>,
    challenges: Collection<Challenge>,
    counters: Collection<Document>,
    blobs: Blobs,
    mailer: Mailer,
    service_key: Arc<SigningKey>,
    /// Identity-signature requests waiting for the cosigner's wallet, by agreement id.
    pending: Arc<Mutex<HashMap<String, IdentityRequest>>>,
    http: reqwest::Client,
}

type AppResult<T> = Result<T, AppError>;

struct AppError(StatusCode, anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        Self(StatusCode::BAD_REQUEST, e.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, format!("{:#}", self.1)).into_response()
    }
}

fn forbidden(msg: &str) -> AppError {
    AppError(StatusCode::FORBIDDEN, anyhow!(msg.to_string()))
}

// ------------------------------------------------------------------ main

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let root = demo_common::app_root()?;
    demo_common::load_dotenv(&root);
    let db = demo_common::database().await?;

    let mut templates = Vec::new();
    for entry in std::fs::read_dir(root.join("templates"))? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "json") {
            templates.push(serde_json::from_str::<Template>(&std::fs::read_to_string(&path)?).with_context(|| path.display().to_string())?);
        }
    }
    templates.sort_by(|a, b| a.title.cmp(&b.title));

    let app = App {
        service_key: Arc::new(load_ed25519_pem(&pki(&root, "consent-o-tron.key")?)?),
        templates: Arc::new(templates),
        agreements: db.collection("agreements"),
        sessions: db.collection("sessions"),
        challenges: db.collection("challenges"),
        counters: db.collection("counters"),
        blobs: Blobs::from_env(&root)?,
        mailer: Mailer::new("consent-o-tron", &db),
        pending: Default::default(),
        http: reqwest::Client::new(),
        root,
    };

    let router = Router::new()
        .route("/", get(home))
        .route("/new", get(new_agreement))
        .route("/new/{template}", get(template_form).post(create_agreement))
        .route("/a/{id}", get(agreement_page))
        .route("/a/{id}/asset", get(asset))
        .route("/a/{id}/signed.jpg", get(signed_file))
        .route("/a/{id}/verify", get(verify_agreement))
        .route("/a/{id}/withdraw", post(withdraw))
        .route("/verify", get(verify_form).post(verify_upload))
        .route("/status/1", get(status_list))
        .route("/api/challenge", get(challenge))
        .route("/api/login", post(login))
        .route("/api/a/{id}/producer-proof", post(producer_proof))
        .route("/api/a/{id}/cosigner", post(cosigner_connect))
        .route("/api/a/{id}/participant-proof", post(participant_proof))
        .route("/api/a/{id}/status", get(agreement_status))
        .route("/api/a/{id}/identity-signature", post(identity_signature))
        .route("/outbox", get(outbox))
        .route("/static/style.css", get(demo_common::style_css))
        .route("/static/wallet-client.js", get(demo_common::wallet_client_js))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD + 64 * 1024))
        .with_state(app.clone());

    println!(
        "Consent-o-tron on {CONSENT_SITE}  (files: {}, email: {}, status list signer {})",
        app.blobs.description,
        if app.mailer.uses_resend() { "Resend" } else { "outbox only" },
        did_key(&app.service_key.verifying_key()),
    );
    let listener = tokio::net::TcpListener::bind(demo_common::listen_addr(4003)).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

// ------------------------------------------------------------------ helpers

async fn load(app: &App, id: &str) -> AppResult<Agreement> {
    app.agreements
        .find_one(doc! { "_id": id })
        .await?
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, anyhow!("unknown agreement")))
}

async fn set(app: &App, id: &str, fields: Document) -> AppResult<()> {
    app.agreements.update_one(doc! { "_id": id }, doc! { "$set": fields }).await?;
    Ok(())
}

async fn current_user(app: &App, headers: &HeaderMap) -> AppResult<Option<WebSession>> {
    let token = headers
        .get(header::COOKIE)
        .and_then(|c| c.to_str().ok())
        .and_then(|c| c.split(';').map(str::trim).find_map(|kv| kv.strip_prefix("cot=")))
        .map(str::to_string);
    Ok(match token {
        Some(t) => app.sessions.find_one(doc! { "_id": t }).await?,
        None => None,
    })
}

/// Consumes a one-time sign-in challenge.
async fn take_challenge(app: &App, value: &str) -> AppResult<()> {
    if app.challenges.find_one_and_delete(doc! { "_id": value }).await?.is_none() {
        return Err(anyhow!("challenge expired or already used").into());
    }
    Ok(())
}

/// What the wallet returns for `connect`.
#[derive(Deserialize)]
struct WalletLogin {
    challenge: String,
    did: String,
    #[serde(rename = "certChainPem")]
    cert_chain_pem: Option<String>,
    signature: String,
}

struct Verified {
    did: String,
    email: String,
    chain_pem: String,
}

/// Checks the challenge signature, and that the certificate chain is from
/// the CAWG test CA and is for the same key.
async fn check_login(app: &App, login: &WalletLogin) -> AppResult<Verified> {
    take_challenge(app, &login.challenge).await?;
    let key = resolve_did_key(&login.did)?;
    let sig = Signature::from_slice(&STANDARD.decode(&login.signature)?)?;
    key.verify(format!("consent-demo-login:{}", login.challenge).as_bytes(), &sig)
        .map_err(|_| anyhow!("wallet signature does not verify"))?;
    let chain_pem = login
        .cert_chain_pem
        .clone()
        .ok_or_else(|| anyhow!("this identity has no certificate yet; get one on the Certificate site"))?;
    let cert = verify_cert_chain(&chain_pem, &pki(&app.root, "cawg-root.pem")?)?;
    if cert.ed25519_key != key.to_bytes() {
        return Err(anyhow!("certificate is for a different key").into());
    }
    let email = cert.emails.first().cloned().ok_or_else(|| anyhow!("certificate has no email"))?;
    Ok(Verified { did: login.did.clone(), email: email.to_lowercase(), chain_pem })
}

fn terms_html(terms: &Value) -> String {
    let rows: String = terms
        .as_object()
        .into_iter()
        .flatten()
        .map(|(k, v)| {
            let v = match v {
                Value::Array(a) => a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "),
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            format!("<dt>{}</dt><dd>{}</dd>", esc(k), esc(v))
        })
        .collect();
    format!(r#"<dl class="terms">{rows}</dl>"#)
}

fn stage_badge(a: &Agreement) -> String {
    let (class, text) = match (a.stage, a.revoked) {
        (_, true) => ("fail", "Consent withdrawn"),
        (Stage::AwaitingProducer, _) => ("", "Waiting for producer signature"),
        (Stage::AwaitingCosigner, _) => ("", "Waiting for consent"),
        (Stage::Authoring, _) => ("", "Writing file"),
        (Stage::Signed, _) => ("ok", "Signed"),
        (Stage::Failed, _) => ("fail", "Failed"),
    };
    format!(r#"<span class="badge {class}">{text}</span>"#)
}

// ------------------------------------------------------------------ sign in

async fn challenge(State(app): State<App>) -> AppResult<Json<Value>> {
    let value = uuid_v4();
    app.challenges.insert_one(Challenge { value: value.clone() }).await?;
    Ok(Json(json!({ "challenge": value })))
}

async fn login(State(app): State<App>, Json(login): Json<WalletLogin>) -> AppResult<Response> {
    let who = check_login(&app, &login).await?;
    let token = uuid_v4();
    app.sessions.insert_one(WebSession { token: token.clone(), did: who.did, email: who.email }).await?;
    Ok(([(header::SET_COOKIE, format!("cot={token}; Path=/; HttpOnly; SameSite=Lax"))], Json(json!({ "ok": true }))).into_response())
}

const SIGN_IN_JS: &str = r#"<script type="module">
import { WalletSession, postJson } from "/static/wallet-client.js";
const status = document.getElementById("status");
document.getElementById("signin").onclick = async () => {
  const wallet = new WalletSession();
  try {
    await wallet.open();
    const { challenge } = await (await fetch("/api/challenge")).json();
    status.textContent = "Choose an identity in your wallet…";
    const who = await wallet.request("connect", { challenge });
    await postJson("/api/login", { challenge, ...who });
    wallet.close();
    location.reload();
  } catch (err) { status.textContent = err.message; wallet.close(); }
};
</script>"#;

async fn home(State(app): State<App>, headers: HeaderMap) -> AppResult<Html<String>> {
    let Some(user) = current_user(&app, &headers).await? else {
        return Ok(SITE.page(
            "Consent, on the record",
            &format!(
                r#"<p>Ask someone for consent to use their image, likeness or voice in a file. Both of you sign, and the consent travels inside the file as a verifiable credential.</p>
<div class="card"><p>Sign in with your wallet. You need a certificate from the <a href="{CERT_SITE}">Certificate site</a> first.</p>
<div class="row actions"><button id="signin">Sign in with wallet</button></div><p id="status" class="muted"></p></div>
<p><a href="/verify">Verify a file</a></p>{SIGN_IN_JS}"#
            ),
        ));
    };
    // Sorted here rather than in the query, so Firestore needs no composite index.
    let mut mine: Vec<Agreement> = app
        .agreements
        .find(doc! { "$or": [ { "producer_did": &user.did }, { "cosigner_email": &user.email } ] })
        .await?
        .try_collect()
        .await?;
    mine.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    let rows: String = mine
        .iter()
        .map(|a| {
            format!(
                r#"<article class="card"><div class="row"><strong><a href="/a/{id}">{}</a></strong>{}</div>
<div class="muted">{} · {} · {}</div></article>"#,
                esc(&a.title),
                stage_badge(a),
                esc(&a.asset_name),
                if a.producer_did == user.did { format!("with {}", esc(&a.cosigner_email)) } else { format!("from {}", esc(&a.producer_email)) },
                esc(&a.created_at),
                id = esc(&a.id),
            )
        })
        .collect();
    Ok(SITE.page(
        "Your agreements",
        &format!(
            r#"<p class="muted">Signed in as {}</p><div class="row"><a class="button" href="/new">New agreement</a><a href="/verify">Verify a file</a></div>
{}"#,
            esc(&user.email),
            if rows.is_empty() { "<p class=\"muted\">No agreements yet.</p>".into() } else { rows }
        ),
    ))
}

// ------------------------------------------------------------------ producer: create

async fn new_agreement(State(app): State<App>, headers: HeaderMap) -> AppResult<Response> {
    if current_user(&app, &headers).await?.is_none() {
        return Ok(Redirect::to("/").into_response());
    }
    let cards: String = app
        .templates
        .iter()
        .map(|t| {
            format!(
                r#"<a class="card" style="display:block;color:inherit;text-decoration:none" href="/new/{}"><strong>{}</strong><p class="muted">{}</p></a>"#,
                esc(&t.id),
                esc(&t.title),
                esc(&t.description)
            )
        })
        .collect();
    Ok(SITE.page("Choose an agreement", &cards).into_response())
}

fn field_html(f: &Field, prefix: &str) -> String {
    let name = format!("{prefix}{}", f.name);
    match f.kind.as_str() {
        "multiselect" => {
            let selected: Vec<&str> = f.default.as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            let boxes: String = f
                .options
                .iter()
                .map(|o| {
                    format!(
                        r#"<label style="display:inline-flex;gap:6px;margin-right:14px;font-weight:400"><input type="checkbox" style="width:auto" name="{}" value="{}" {}/>{}</label>"#,
                        esc(&name),
                        esc(o),
                        if selected.contains(&o.as_str()) { "checked " } else { "" },
                        esc(o)
                    )
                })
                .collect();
            format!(r#"<fieldset style="border:0;padding:0;margin:12px 0"><legend style="font-weight:500">{}</legend>{boxes}</fieldset>"#, esc(&f.label))
        }
        "select" => {
            let opts: String = f
                .options
                .iter()
                .map(|o| format!(r#"<option {}>{}</option>"#, if f.default == o.as_str() { "selected" } else { "" }, esc(o)))
                .collect();
            format!(r#"<label>{}<select name="{}">{opts}</select></label>"#, esc(&f.label), esc(&name))
        }
        _ => format!(
            r#"<label>{}<input name="{}" value="{}" required /></label>"#,
            esc(&f.label),
            esc(&name),
            esc(f.default.as_str().unwrap_or_default())
        ),
    }
}

async fn template_form(State(app): State<App>, headers: HeaderMap, UrlPath(tid): UrlPath<String>) -> AppResult<Response> {
    if current_user(&app, &headers).await?.is_none() {
        return Ok(Redirect::to("/").into_response());
    }
    let t = app.templates.iter().find(|t| t.id == tid).ok_or_else(|| anyhow!("unknown template"))?;
    let public: String = t.public.iter().map(|f| field_html(f, "public.")).collect();
    let private: String = t.private.iter().map(|f| field_html(f, "private.")).collect();
    Ok(SITE
        .page(
            &t.title,
            &format!(
                r#"<p class="muted">{}</p>
<form class="card" method="post" enctype="multipart/form-data">
  <h2>The file</h2>
  <label>Image (JPEG, up to 25 MB)<input type="file" name="asset" accept="image/jpeg" required /></label>
  <h2>Who is giving consent</h2>
  <label>Their email<input type="email" name="cosigner_email" required placeholder="performer@example.com" /></label>
  <p class="muted">The credential names them by this email; it must match the email on their certificate.</p>
  <h2>Public terms</h2><p class="muted">Anyone who has the file can read these.</p>{public}
  <h2>Private terms</h2><p class="muted">Only a salted hash goes in the file. The text stays between you and the person consenting.</p>{private}
  <div class="row actions"><button>Create credential</button></div>
</form>"#,
                esc(&t.description)
            ),
        )
        .into_response())
}

async fn create_agreement(
    State(app): State<App>,
    headers: HeaderMap,
    UrlPath(tid): UrlPath<String>,
    mut form: Multipart,
) -> AppResult<Redirect> {
    let user = current_user(&app, &headers).await?.ok_or_else(|| forbidden("sign in first"))?;
    let t = app.templates.iter().find(|t| t.id == tid).ok_or_else(|| anyhow!("unknown template"))?.clone();

    let mut values: HashMap<String, Vec<String>> = HashMap::new();
    let (mut asset, mut asset_name) = (Vec::new(), String::new());
    while let Some(field) = form.next_field().await? {
        let name = field.name().unwrap_or_default().to_string();
        if name == "asset" {
            asset_name = field.file_name().unwrap_or("upload.jpg").to_string();
            asset = field.bytes().await?.to_vec();
        } else {
            values.entry(name).or_default().push(field.text().await?);
        }
    }
    if asset.len() < 4 || asset[..3] != [0xff, 0xd8, 0xff] {
        return Err(anyhow!("please upload a JPEG image").into());
    }
    let cosigner_email = values.get("cosigner_email").and_then(|v| v.first()).map(|s| s.trim().to_lowercase()).unwrap_or_default();
    if !cosigner_email.contains('@') {
        return Err(anyhow!("enter the email of the person giving consent").into());
    }

    let value_of = |prefix: &str, f: &Field| -> Value {
        let got = values.get(&format!("{prefix}{}", f.name)).cloned().unwrap_or_default();
        if f.kind == "multiselect" {
            json!(got)
        } else {
            json!(got.first().map(|s| s.trim().to_string()).unwrap_or_default())
        }
    };
    let consent: serde_json::Map<String, Value> = t.public.iter().map(|f| (f.name.clone(), value_of("public.", f))).collect();
    let private: serde_json::Map<String, Value> = t.private.iter().map(|f| (f.name.clone(), value_of("private.", f))).collect();

    // Render the agreement text from both sets of fields.
    let mut text = t.agreement.clone();
    for (k, v) in consent.iter().chain(private.iter()) {
        let v = match v {
            Value::Array(a) => a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "),
            other => other.as_str().unwrap_or_default().to_string(),
        };
        text = text.replace(&format!("{{{{{k}}}}}"), &v);
    }
    text = text.replace("{{participant}}", &cosigner_email).replace("{{producer}}", &user.email);

    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    let agreement_doc = json!({ "template": t.id, "terms": private, "text": text, "producer": user.email, "participant": cosigner_email });
    let index = next_status_index(&app).await?;
    let subject = format!("mailto:{cosigner_email}");
    let asset_hash = sha256_b64(&asset);
    let credential = build_credential(&CredentialParams {
        issuer_did: &user.did,
        subject_id: &subject,
        asset_hash_b64: &asset_hash,
        credential_type: &t.credential_type,
        industry_schema_id: &t.schema_id,
        status_list_url: &status_list_url(),
        status_index: index,
        governance_framework: &registry_authority(),
        trust_registry: REGISTRY_URL.get(),
        consent: Value::Object(consent),
        agreement: &agreement_doc,
        salt: &salt,
        valid_from: &now(),
    })?;

    let id = uuid_v4();
    let asset_key = format!("agreements/{id}/original.jpg");
    app.blobs.put(&asset_key, asset).await?;
    app.agreements
        .insert_one(Agreement {
            id: id.clone(),
            created_at: now(),
            template_id: t.id.clone(),
            title: t.title.clone(),
            producer_did: user.did,
            producer_email: user.email,
            cosigner_email,
            invite_token: uuid_v4(),
            asset_name,
            asset_key,
            asset_hash,
            credential: credential.to_string(),
            private_agreement: json!({ "salt": STANDARD.encode(salt), "agreement": agreement_doc }).to_string(),
            agreement_text: text,
            producer_proof: None,
            participant_proof: None,
            cosigner_did: None,
            cosigner_chain_pem: None,
            status_index: index as i64,
            revoked: false,
            stage: Stage::AwaitingProducer,
            error: None,
            signed_key: None,
        })
        .await?;
    Ok(Redirect::to(&format!("/a/{id}")))
}

async fn next_status_index(app: &App) -> AppResult<usize> {
    let counter = app
        .counters
        .find_one_and_update(doc! { "_id": "status" }, doc! { "$inc": { "next": 1_i64 } })
        .with_options(FindOneAndUpdateOptions::builder().upsert(true).return_document(ReturnDocument::After).build())
        .await?
        .ok_or_else(|| anyhow!("status counter"))?;
    Ok(counter.get_i64("next")? as usize)
}

// ------------------------------------------------------------------ agreement page

#[derive(Deserialize)]
struct InviteQuery {
    invite: Option<String>,
}

enum Viewer {
    Producer,
    Cosigner(String),
    Other,
}

async fn viewer(app: &App, headers: &HeaderMap, a: &Agreement, invite: Option<&str>) -> AppResult<Viewer> {
    if invite == Some(a.invite_token.as_str()) {
        return Ok(Viewer::Cosigner(a.invite_token.clone()));
    }
    Ok(match current_user(app, headers).await? {
        Some(u) if u.did == a.producer_did => Viewer::Producer,
        _ => Viewer::Other,
    })
}

async fn agreement_page(
    State(app): State<App>,
    headers: HeaderMap,
    UrlPath(id): UrlPath<String>,
    Query(q): Query<InviteQuery>,
) -> AppResult<Html<String>> {
    let a = load(&app, &id).await?;
    let who = viewer(&app, &headers, &a, q.invite.as_deref()).await?;
    if matches!(who, Viewer::Other) {
        return Err(forbidden("only the producer and the person giving consent can open this agreement"));
    }

    // The wallet shows the image straight from this URL.
    let asset_meta = json!({ "name": a.asset_name, "hash": a.asset_hash, "thumbnail": format!("{CONSENT_SITE}/a/{}/asset", a.id) });
    let summary = format!(
        r#"<div class="row"><span class="muted">Between {} and {}</span>{}</div>
<figure class="asset large"><img src="/a/{id}/asset" alt="" /><figcaption class="mono muted">{} · sha256 {}</figcaption></figure>
<h2>Public terms</h2>{}
<h2>Private agreement</h2><pre class="agreement">{}</pre>
<p class="muted">The file carries only a salted hash of this text.</p>
<details class="card"><summary>Credential</summary><pre class="agreement">{}</pre></details>"#,
        esc(&a.producer_email),
        esc(&a.cosigner_email),
        stage_badge(&a),
        esc(&a.asset_name),
        esc(&a.asset_hash),
        terms_html(&a.public_terms()),
        esc(&a.agreement_text),
        esc(serde_json::to_string_pretty(&a.credential_with_proofs()).unwrap_or_default()),
        id = esc(&a.id),
    );

    let action = match (&who, a.stage) {
        (Viewer::Producer, Stage::AwaitingProducer) => format!(
            r#"<div class="card"><p>Sign the consent request with your wallet. Consent-o-tron then emails <strong>{}</strong>.</p>
<div class="row actions"><button id="sign">Sign with wallet</button></div><p id="status" class="muted"></p></div>
<script type="module">
import {{ WalletSession, postJson }} from "/static/wallet-client.js";
const credential = {credential}, asset = {asset}, agreementText = {text};
const status = document.getElementById("status");
document.getElementById("sign").onclick = async () => {{
  const wallet = new WalletSession();
  try {{
    await wallet.open();
    status.textContent = "Approve in your wallet…";
    const {{ proof }} = await wallet.request("credential:sign", {{ credential, role: "issuer", asset, agreementText, counterparty: {counterparty} }});
    await postJson("/api/a/{id}/producer-proof", {{ proof }});
    wallet.close();
    location.reload();
  }} catch (err) {{ status.textContent = err.message; wallet.close(); }}
}};
</script>"#,
            esc(&a.cosigner_email),
            credential = script_json(&a.unsecured()),
            asset = script_json(&asset_meta),
            text = script_json(&a.agreement_text),
            counterparty = script_json(&a.cosigner_email),
            id = esc(&a.id),
        ),
        (Viewer::Producer, Stage::AwaitingCosigner) => format!(
            r#"<p class="notice">Sent to {}. The file is written once they consent.</p>"#,
            esc(&a.cosigner_email)
        ),
        (Viewer::Cosigner(invite), Stage::AwaitingCosigner) => format!(
            r#"<div class="card"><p><strong>{}</strong> asks for your consent on the terms below.</p>
<p class="muted">Your wallet signs twice: once to consent, and once to attach your identity to the finished file.</p>
<div class="row actions"><button id="consent">Consent with wallet</button></div><p id="status" class="muted"></p></div>
<script type="module">
import {{ WalletSession, postJson }} from "/static/wallet-client.js";
const credential = {credential}, asset = {asset}, agreementText = {text}, invite = {invite};
const status = document.getElementById("status");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
document.getElementById("consent").onclick = async () => {{
  const wallet = new WalletSession();
  try {{
    await wallet.open();
    const {{ challenge }} = await (await fetch("/api/challenge")).json();
    status.textContent = "Choose your identity in the wallet…";
    const who = await wallet.request("connect", {{ challenge }});
    await postJson("/api/a/{id}/cosigner", {{ invite, challenge, ...who }});
    status.textContent = "Review and consent in your wallet…";
    const {{ proof }} = await wallet.request("credential:sign", {{ credential, role: "participant", asset, agreementText, counterparty: {counterparty} }});
    await postJson("/api/a/{id}/participant-proof", {{ invite, proof }});
    status.textContent = "Writing the file…";
    for (;;) {{
      const s = await (await fetch("/api/a/{id}/status?invite=" + encodeURIComponent(invite))).json();
      if (s.identityRequest) {{
        status.textContent = "Attach your identity in the wallet…";
        const {{ signature }} = await wallet.request("identity:sign", {{ ...s.identityRequest, asset }});
        await postJson("/api/a/{id}/identity-signature", {{ invite, signature }});
        status.textContent = "Writing the file…";
      }}
      if (s.stage === "signed") break;
      if (s.stage === "failed") throw new Error(s.error || "authoring failed");
      await sleep(600);
    }}
    wallet.close();
    location.reload();
  }} catch (err) {{ status.textContent = err.message; wallet.close(); }}
}};
</script>"#,
            esc(&a.producer_email),
            credential = script_json(&a.unsecured()),
            asset = script_json(&asset_meta),
            text = script_json(&a.agreement_text),
            invite = script_json(invite),
            counterparty = script_json(&a.producer_email),
            id = esc(&a.id),
        ),
        (_, Stage::Authoring) => r#"<p class="notice">Writing the file…</p>"#.into(),
        (_, Stage::Failed) => format!(r#"<p class="notice warn">Authoring failed: {}</p>"#, esc(a.error.as_deref().unwrap_or("unknown error"))),
        (_, Stage::Signed) => {
            let invite_q = match &who {
                Viewer::Cosigner(t) => format!("?invite={}", esc(t)),
                _ => String::new(),
            };
            let withdraw = match (&who, a.revoked) {
                (Viewer::Cosigner(t), false) => format!(
                    r#"<form method="post" action="/a/{id}/withdraw" onsubmit="return confirm('Withdraw your consent? The file stays signed, but verifiers will see consent as withdrawn.')">
<input type="hidden" name="invite" value="{}" /><button class="secondary danger">Withdraw consent</button></form>"#,
                    esc(t),
                    id = esc(&a.id)
                ),
                _ => String::new(),
            };
            format!(
                r#"<div class="card"><p>The file is signed by Consent-o-tron and carries the consent credential and {}'s identity assertion.</p>
<div class="row actions">{withdraw}<a class="button secondary" href="/a/{id}/verify{invite_q}">Verify</a><a class="button" href="/a/{id}/signed.jpg" download>Download signed file</a></div></div>"#,
                esc(&a.cosigner_email),
                id = esc(&a.id),
            )
        }
        _ => String::new(),
    };
    Ok(SITE.page(&a.title, &format!("{action}{summary}")))
}

async fn asset(State(app): State<App>, UrlPath(id): UrlPath<String>) -> AppResult<Response> {
    let a = load(&app, &id).await?;
    Ok(([(header::CONTENT_TYPE, "image/jpeg")], app.blobs.get(&a.asset_key).await?).into_response())
}

async fn signed_file(State(app): State<App>, UrlPath(id): UrlPath<String>) -> AppResult<Response> {
    let a = load(&app, &id).await?;
    let bytes = app.blobs.get(a.signed_key.as_deref().ok_or_else(|| anyhow!("not signed yet"))?).await?;
    let stem = a.asset_name.trim_end_matches(".jpg").trim_end_matches(".jpeg").replace('"', "");
    Ok((
        [(header::CONTENT_TYPE, "image/jpeg".to_string()), (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{stem}-signed.jpg\""))],
        bytes,
    )
        .into_response())
}

// ------------------------------------------------------------------ signing API

#[derive(Deserialize)]
struct ProofBody {
    proof: Value,
    invite: Option<String>,
}

/// Verifies one proof against the unsecured credential; returns its signer's key.
fn check_proof(a: &Agreement, proof: &Value) -> AppResult<[u8; 32]> {
    let mut credential = a.unsecured();
    credential["proof"] = json!([proof]);
    let result = verify_proofs(&credential)?.pop().ok_or_else(|| anyhow!("no proof"))?;
    if !result.valid {
        return Err(anyhow!("the proof does not verify").into());
    }
    Ok(resolve_did_key(&result.verification_method)?.to_bytes())
}

async fn producer_proof(State(app): State<App>, headers: HeaderMap, UrlPath(id): UrlPath<String>, Json(body): Json<ProofBody>) -> AppResult<Json<Value>> {
    let a = load(&app, &id).await?;
    if !matches!(viewer(&app, &headers, &a, None).await?, Viewer::Producer) || a.stage != Stage::AwaitingProducer {
        return Err(forbidden("not waiting for the producer's signature"));
    }
    check_proof(&a, &body.proof)?;
    if did_of_vm(body.proof["verificationMethod"].as_str().unwrap_or_default()) != a.producer_did {
        return Err(anyhow!("the proof must be made by the issuer").into());
    }
    set(&app, &id, doc! { "producer_proof": body.proof.to_string(), "stage": "awaiting_cosigner" }).await?;
    app.mailer
        .send(
            &a.cosigner_email,
            &format!("{} asks for your consent", a.producer_email),
            &format!(
                "{} asked for your consent: {} for {}. Review the terms and the file before you decide.",
                a.producer_email, a.title, a.asset_name
            ),
            &format!("{CONSENT_SITE}/a/{id}?invite={}", a.invite_token),
        )
        .await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct CosignerBody {
    invite: String,
    #[serde(flatten)]
    login: WalletLogin,
}

async fn cosigner_connect(State(app): State<App>, UrlPath(id): UrlPath<String>, Json(body): Json<CosignerBody>) -> AppResult<Json<Value>> {
    let a = load(&app, &id).await?;
    if body.invite != a.invite_token || a.stage != Stage::AwaitingCosigner {
        return Err(forbidden("this invitation is not waiting for consent"));
    }
    let who = check_login(&app, &body.login).await?;
    if who.email != a.cosigner_email {
        return Err(anyhow!("this agreement is for {}; your certificate is for {}", a.cosigner_email, who.email).into());
    }
    set(&app, &id, doc! { "cosigner_did": who.did, "cosigner_chain_pem": who.chain_pem }).await?;
    Ok(Json(json!({ "ok": true })))
}

async fn participant_proof(State(app): State<App>, UrlPath(id): UrlPath<String>, Json(body): Json<ProofBody>) -> AppResult<Json<Value>> {
    let a = load(&app, &id).await?;
    if body.invite.as_deref() != Some(a.invite_token.as_str()) || a.stage != Stage::AwaitingCosigner {
        return Err(forbidden("this invitation is not waiting for consent"));
    }
    let cosigner = a.cosigner_did.clone().ok_or_else(|| anyhow!("connect your wallet first"))?;
    let chain = a.cosigner_chain_pem.clone().ok_or_else(|| anyhow!("connect your wallet first"))?;
    if check_proof(&a, &body.proof)? != resolve_did_key(&cosigner)?.to_bytes() {
        return Err(anyhow!("the consent must be signed by the identity you connected").into());
    }
    set(&app, &id, doc! { "participant_proof": body.proof.to_string(), "stage": "authoring" }).await?;

    let a = load(&app, &id).await?;
    let credential = a.credential_with_proofs();
    let asset = app.blobs.get(&a.asset_key).await?;
    let wallet = WalletSigner {
        post: Box::new({
            let (pending, id) = (app.pending.clone(), id.clone());
            move |request| {
                pending.lock().unwrap().insert(id.clone(), request);
            }
        }),
    };
    let task_app = app.clone();
    tokio::spawn(async move {
        let root = task_app.root.clone();
        let result = tokio::task::spawn_blocking(move || authoring::author(&root, &asset, &credential, &chain, wallet)).await;
        task_app.pending.lock().unwrap().remove(&id);
        let update = match result {
            Ok(Ok(bytes)) => {
                let key = format!("agreements/{id}/signed.jpg");
                match task_app.blobs.put(&key, bytes).await {
                    Ok(()) => doc! { "stage": "signed", "signed_key": key },
                    Err(e) => doc! { "stage": "failed", "error": format!("storing the signed file: {e:#}") },
                }
            }
            Ok(Err(e)) => doc! { "stage": "failed", "error": format!("{e:#}") },
            Err(e) => doc! { "stage": "failed", "error": e.to_string() },
        };
        if let Err(e) = task_app.agreements.update_one(doc! { "_id": &id }, doc! { "$set": update }).await {
            eprintln!("saving authoring result for {id}: {e}");
        }
    });
    Ok(Json(json!({ "ok": true })))
}

async fn agreement_status(State(app): State<App>, UrlPath(id): UrlPath<String>, Query(q): Query<InviteQuery>) -> AppResult<Json<Value>> {
    let a = load(&app, &id).await?;
    let mut out = json!({ "stage": a.stage, "error": a.error });
    if q.invite.as_deref() == Some(a.invite_token.as_str()) {
        if let Some(req) = app.pending.lock().unwrap().get(&id) {
            out["identityRequest"] = json!({
                "toBeSigned": STANDARD.encode(&req.to_be_signed),
                "consentHash": STANDARD.encode(&req.consent_hash),
            });
        }
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
struct SignatureBody {
    invite: String,
    signature: String,
}

async fn identity_signature(State(app): State<App>, UrlPath(id): UrlPath<String>, Json(body): Json<SignatureBody>) -> AppResult<Json<Value>> {
    let a = load(&app, &id).await?;
    if body.invite != a.invite_token {
        return Err(forbidden("wrong invitation"));
    }
    let signature = STANDARD.decode(&body.signature)?;
    let request = app.pending.lock().unwrap().remove(&id).ok_or_else(|| anyhow!("no identity signature is pending"))?;
    // Check it before handing it to c2pa-rs, so a bad signature fails here.
    let key = resolve_did_key(a.cosigner_did.as_deref().unwrap_or_default())?;
    key.verify(&request.to_be_signed, &Signature::from_slice(&signature)?)
        .map_err(|_| anyhow!("identity signature does not verify"))?;
    request.reply.send(signature).map_err(|_| anyhow!("authoring is no longer waiting"))?;
    Ok(Json(json!({ "ok": true })))
}

// ------------------------------------------------------------------ withdrawal + status list

#[derive(Deserialize)]
struct WithdrawForm {
    invite: String,
}

async fn withdraw(State(app): State<App>, UrlPath(id): UrlPath<String>, axum::Form(form): axum::Form<WithdrawForm>) -> AppResult<Redirect> {
    let a = load(&app, &id).await?;
    if form.invite != a.invite_token {
        return Err(forbidden("only the person who consented can withdraw"));
    }
    set(&app, &id, doc! { "revoked": true }).await?;
    Ok(Redirect::to(&format!("/a/{id}/verify?invite={}", a.invite_token)))
}

fn status_list_url() -> String {
    format!("{CONSENT_SITE}/status/1")
}

async fn signed_status_list(app: &App) -> AppResult<Value> {
    let revoked: Vec<Agreement> = app.agreements.find(doc! { "revoked": true }).await?.try_collect().await?;
    let indices: Vec<usize> = revoked.iter().map(|a| a.status_index as usize).collect();
    let mut list = build_status_list(&status_list_url(), &did_key(&app.service_key.verifying_key()), &indices)?;
    add_proof(&mut list, &app.service_key, &now())?;
    Ok(list)
}

async fn status_list(State(app): State<App>) -> AppResult<Json<Value>> {
    Ok(Json(signed_status_list(&app).await?))
}

// ------------------------------------------------------------------ verify

#[derive(Deserialize)]
struct VerifyQuery {
    invite: Option<String>,
    offline: Option<String>,
    reveal: Option<String>,
}

/// Online: the guild's trust registry (asked over TRQP) and this site's
/// status list. Offline: neither.
async fn verify_inputs(app: &App, offline: bool, agreement: Option<Value>) -> AppResult<Inputs> {
    if offline {
        return Ok(Inputs { agreement, ..Default::default() });
    }
    Ok(Inputs {
        trqp: Some(trqp_client(app.http.clone())),
        trusted_authority: Some(registry_authority()),
        status_list: Some(signed_status_list(app).await?),
        agreement,
    })
}

/// Asks the trust registry `POST /authorization` (TRQP 2.0), passing the
/// question's time as `context.time`. The verifier is synchronous, so this
/// blocks on the async client; it runs on the multi-threaded runtime.
fn trqp_client(http: reqwest::Client) -> TrqpQuery {
    let handle = tokio::runtime::Handle::current();
    Box::new(move |q: &TrqpQuestion| {
        let mut body = json!({ "entity_id": q.entity_id, "authority_id": q.authority_id, "action": q.action, "resource": q.resource });
        if let Some(time) = q.time {
            body["context"] = json!({ "time": time });
        }
        let (http, handle) = (http.clone(), handle.clone());
        tokio::task::block_in_place(move || {
            handle.block_on(async move {
                let answer: Value = http.post(format!("{REGISTRY_URL}/authorization")).json(&body).send().await?.error_for_status()?.json().await?;
                answer["authorized"].as_bool().ok_or_else(|| anyhow!("TRQP response has no authorized field"))
            })
        })
    })
}

fn report_html(report: &Report) -> String {
    let creds: String = report
        .credentials
        .iter()
        .map(|c| {
            let outcomes: String = c
                .outcomes
                .iter()
                .map(|o| {
                    format!(
                        r#"<li><span class="{}">{}</span><div><div class="code">{}</div><div class="muted">{}</div></div></li>"#,
                        if o.pass { "pass" } else { "fail" },
                        if o.pass { "✓" } else { "✗" },
                        esc(&o.code),
                        esc(&o.explanation)
                    )
                })
                .collect();
            format!(
                r#"<article class="card"><div class="row"><strong>Consent credential</strong><span class="badge {}">{}</span></div>
<div class="muted">Subject {} · signed {}</div><h3>Public terms</h3>{}<h3>Checks</h3><ul class="outcomes">{outcomes}</ul></article>"#,
                if c.valid { "ok" } else { "fail" },
                if c.valid { "valid" } else { "not valid" },
                esc(c.subject.trim_start_matches("mailto:")),
                esc(&c.valid_from),
                terms_html(&c.public_terms),
            )
        })
        .collect();
    let failures: String = report
        .c2pa_failures
        .iter()
        .map(|f| format!(r#"<li class="mono">{} {}</li>"#, esc(&f.code), esc(&f.url)))
        .collect();
    format!(
        r#"<div class="card"><div class="row"><strong>C2PA manifest</strong><span class="badge {}">{}</span></div>{}</div>{creds}"#,
        if matches!(report.c2pa_state.as_str(), "Trusted" | "Valid") { "ok" } else { "fail" },
        esc(&report.c2pa_state),
        if failures.is_empty() { String::new() } else { format!("<ul>{failures}</ul>") }
    )
}

async fn verify_agreement(
    State(app): State<App>,
    headers: HeaderMap,
    UrlPath(id): UrlPath<String>,
    Query(q): Query<VerifyQuery>,
) -> AppResult<Html<String>> {
    let a = load(&app, &id).await?;
    let who = viewer(&app, &headers, &a, q.invite.as_deref()).await?;
    let signed = app.blobs.get(a.signed_key.as_deref().ok_or_else(|| anyhow!("not signed yet"))?).await?;
    let offline = q.offline.is_some();
    let party = !matches!(who, Viewer::Other);
    let agreement = if q.reveal.is_some() && party { serde_json::from_str(&a.private_agreement).ok() } else { None };
    let inputs = verify_inputs(&app, offline, agreement).await?;
    let report = verify_asset(&app.root, "image/jpeg", &signed, &inputs)?;

    let base = match &q.invite {
        Some(t) => format!("/a/{}/verify?invite={}&", esc(&id), esc(t)),
        None => format!("/a/{}/verify?", esc(&id)),
    };
    let reveal = if party {
        format!(r#"<a class="button secondary" href="{base}{}reveal=1">Reveal private agreement</a>"#, if offline { "offline=1&" } else { "" })
    } else {
        String::new()
    };
    Ok(SITE.page(
        "Verify",
        &format!(
            r#"<p class="muted">{} · <a href="/a/{id}{back}">back to agreement</a></p>
<div class="row" style="justify-content:flex-start"><a class="button {on}" href="{base}">Online</a><a class="button {off}" href="{base}offline=1">Offline</a>{reveal}</div>
<p class="muted">Offline skips the trust registry and the status list, the way a disconnected reader would.</p>{}"#,
            esc(&a.asset_name),
            report_html(&report),
            id = esc(&id),
            back = q.invite.as_ref().map(|t| format!("?invite={}", esc(t))).unwrap_or_default(),
            on = if offline { "secondary" } else { "" },
            off = if offline { "" } else { "secondary" },
        ),
    ))
}

async fn verify_form() -> Html<String> {
    SITE.page(
        "Verify a file",
        r#"<form class="card" method="post" enctype="multipart/form-data">
<label>Signed file (JPEG)<input type="file" name="file" accept="image/jpeg" required /></label>
<label style="font-weight:400"><input type="checkbox" name="offline" style="width:auto" /> Offline (skip trust registry and status list)</label>
<div class="row actions"><button>Verify</button></div></form>"#,
    )
}

async fn verify_upload(State(app): State<App>, mut form: Multipart) -> AppResult<Html<String>> {
    let (mut file, mut offline) = (Vec::new(), false);
    while let Some(field) = form.next_field().await? {
        match field.name() {
            Some("file") => file = field.bytes().await?.to_vec(),
            Some("offline") => offline = true,
            _ => {}
        }
    }
    let inputs = verify_inputs(&app, offline, None).await?;
    let body = match verify_asset(&app.root, "image/jpeg", &file, &inputs) {
        Ok(report) => report_html(&report),
        Err(e) => format!(r#"<p class="notice warn">{}</p>"#, esc(format!("{e:#}"))),
    };
    Ok(SITE.page("Verify a file", &format!(r#"<p><a href="/verify">Verify another</a></p>{body}"#)))
}

async fn outbox(State(app): State<App>) -> AppResult<Html<String>> {
    Ok(app.mailer.outbox_page(&SITE).await?)
}
