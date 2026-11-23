//! Consent-O-Tron (http://localhost:4003).
//!
//! The pages are a React app in web/, built to web/dist; this server
//! returns its index.html for every page route and answers its JSON API.
//!
//! Producer: sign in with wallet → pick an agreement template → upload the
//! file, name the person giving consent, fill in the terms → sign the
//! credential. Cosigner: open the emailed link → review terms, agreement
//! and file → consent with their wallet → their wallet also signs the CAWG
//! identity assertion while Consent-O-Tron authors the final file.
//!
//! Consent-O-Tron also runs the status list (withdrawal) under its own
//! service key, and verifies any file.
//!
//! Records live in MongoDB (`agreements`, `sessions`, `challenges`,
//! `counters`, `outbox`); uploaded and signed files in the GCS bucket (or
//! data/blobs/ locally). The one thing kept in memory is the hand-off to
//! the cosigner's wallet while a file is being authored.

mod authoring;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, Context as _};
use authoring::{IdentityRequest, WalletSigner};
use axum::{
    extract::{DefaultBodyLimit, Multipart, Path as UrlPath, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use cawg_consent_test::{
    add_proof, build_credential, build_status_list, did_key, did_of_vm, hard_binding_sha256, load_ed25519_pem, now, pki, resolve_did_key,
    uuid_v4,
    verify::{governed_type, verify_asset, Inputs, Report, TrqpQuery, TrqpQuestion},
    verify_cert_chain, verify_proofs, CredentialParams, Industry, StatusEntry,
};
use demo_common::{
    mongodb::{
        bson::{doc, Document},
        options::{FindOneAndUpdateOptions, ReturnDocument},
        Collection,
    },
    registry_authority, Blobs, Mailer, CERT_SITE, CONSENT_SITE, REGISTRY_URL,
};
use ed25519_dalek::{Signature, SigningKey, Verifier};
use futures_util::TryStreamExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower_http::services::ServeDir;

const MAX_UPLOAD: usize = 25 * 1024 * 1024;

// ------------------------------------------------------------------ data

#[derive(Clone, Serialize, Deserialize)]
struct Template {
    id: String,
    title: String,
    description: String,
    /// Gallery grouping, e.g. "Editorial".
    #[serde(default)]
    category: String,
    /// Date the template last changed, YYYY-MM-DD.
    #[serde(default)]
    updated: String,
    public: Vec<Field>,
    private: Vec<Field>,
    agreement: String,
    /// The guild credential type and schema. Without them the template makes
    /// a bare CAWG credential: no trust registry, no public terms and no
    /// status list, so its consent can't be withdrawn.
    #[serde(rename = "credentialType", default)]
    credential_type: Option<String>,
    #[serde(rename = "schemaId", default)]
    schema_id: Option<String>,
    /// Offers an optional expiry date (validUntil).
    #[serde(default)]
    expiry: bool,
    /// One party: the producer licenses their own file (consentDomain
    /// `asset`), signing the credential and the identity assertion alone.
    #[serde(rename = "selfSigned", default)]
    self_signed: bool,
}

#[derive(Clone, Serialize, Deserialize)]
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
    /// `{ salt, agreement }`, kept by Consent-O-Tron for the parties.
    private_agreement: String,
    agreement_text: String,
    producer_proof: Option<String>,
    participant_proof: Option<String>,
    cosigner_did: Option<String>,
    cosigner_chain_pem: Option<String>,
    /// None for consent that can't be withdrawn.
    #[serde(default)]
    status_index: Option<i64>,
    revoked: bool,
    /// The producer licenses their own file: no one else signs.
    #[serde(default)]
    self_signed: bool,
    /// The signed withdrawal statement (`Withdrawal` as JSON), once withdrawn.
    #[serde(default)]
    withdrawal: Option<String>,
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

    /// What the wallet shows about the file; it loads the image from this URL.
    fn wallet_asset(&self) -> Value {
        json!({ "name": self.asset_name, "hash": self.asset_hash, "thumbnail": format!("{CONSENT_SITE}/a/{}/asset", self.id) })
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

fn unauthorized() -> AppError {
    AppError(StatusCode::UNAUTHORIZED, anyhow!("log in first"))
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

    let mut router = Router::new();
    for page in ["/", "/demo", "/agreements", "/new/{template}", "/a/{id}", "/a/{id}/verify", "/verify", "/outbox"] {
        router = router.route(page, get(web_index));
    }
    let router = router
        .route("/a/{id}/asset", get(asset))
        .route("/a/{id}/signed.jpg", get(signed_file))
        .route("/status/1", get(status_list))
        .route("/api/challenge", get(challenge))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/config", get(config))
        .route("/api/templates", get(templates_list))
        .route("/api/permissions", get(permissions))
        .route("/api/agreements", get(agreements_list).post(create_agreement))
        .route("/api/a/{id}", get(agreement_view))
        .route("/api/a/{id}/producer-proof", post(producer_proof))
        .route("/api/a/{id}/cosigner", post(cosigner_connect))
        .route("/api/a/{id}/participant-proof", post(participant_proof))
        .route("/api/a/{id}/license", post(license))
        .route("/api/a/{id}/status", get(agreement_status))
        .route("/api/a/{id}/identity-signature", post(identity_signature))
        .route("/api/a/{id}/withdraw", post(withdraw))
        .route("/api/a/{id}/verify", get(verify_agreement))
        .route("/api/verify", post(verify_upload))
        .route("/api/outbox", get(outbox))
        .route("/static/wallet-client.js", get(demo_common::wallet_client_js))
        // Built assets, the mascot and favicons.
        .fallback_service(ServeDir::new(web_dist(&app.root)))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD + 64 * 1024))
        .with_state(app.clone());

    println!(
        "Consent-O-Tron on {CONSENT_SITE}  (files: {}, email: {}, status list signer {})",
        app.blobs.description,
        if app.mailer.uses_resend() { "Resend" } else { "outbox only" },
        did_key(&app.service_key.verifying_key()),
    );
    let listener = tokio::net::TcpListener::bind(demo_common::listen_addr(4003)).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

// ------------------------------------------------------------------ pages

fn web_dist(root: &Path) -> PathBuf {
    root.join("crates/consent-o-tron/web/dist")
}

/// The React app's page; it picks what to show from the path.
async fn web_index(State(app): State<App>) -> AppResult<Html<String>> {
    let path = web_dist(&app.root).join("index.html");
    let html = tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| anyhow!("{}: {e} (run `npm run build` in crates/consent-o-tron/web)", path.display()))?;
    Ok(Html(html))
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

fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|c| c.to_str().ok())
        .and_then(|c| c.split(';').map(str::trim).find_map(|kv| kv.strip_prefix("cot=")))
        .map(str::to_string)
}

async fn current_user(app: &App, headers: &HeaderMap) -> AppResult<Option<WebSession>> {
    Ok(match session_token(headers) {
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
        .ok_or_else(|| anyhow!("this identity has no certificate yet; get one from NotSSL"))?;
    let cert = verify_cert_chain(&chain_pem, &pki(&app.root, "cawg-root.pem")?)?;
    if cert.ed25519_key != key.to_bytes() {
        return Err(anyhow!("certificate is for a different key").into());
    }
    let email = cert.emails.first().cloned().ok_or_else(|| anyhow!("certificate has no email"))?;
    Ok(Verified { did: login.did.clone(), email: email.to_lowercase(), chain_pem })
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
    let body = json!({ "email": who.email, "did": who.did });
    app.sessions.insert_one(WebSession { token: token.clone(), did: who.did, email: who.email }).await?;
    Ok(([(header::SET_COOKIE, format!("cot={token}; Path=/; HttpOnly; SameSite=Lax"))], Json(body)).into_response())
}

async fn logout(State(app): State<App>, headers: HeaderMap) -> AppResult<Response> {
    if let Some(token) = session_token(&headers) {
        app.sessions.delete_one(doc! { "_id": token }).await?;
    }
    Ok(([(header::SET_COOKIE, "cot=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")], Json(json!({ "ok": true }))).into_response())
}

async fn me(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    Ok(Json(match current_user(&app, &headers).await? {
        Some(u) => json!({ "email": u.email, "did": u.did }),
        None => Value::Null,
    }))
}

/// Site URLs the pages link to, which differ per deployment.
async fn config() -> Json<Value> {
    Json(json!({ "certSite": CERT_SITE.get(), "requestAccess": request_access_url() }))
}

/// Which templates the signed-in producer may issue, as the trust registry
/// answers now: template id → null, or the registry's reason for refusing.
/// `unavailable` when the registry can't be asked; creating checks again.
async fn permissions(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = current_user(&app, &headers).await?.ok_or_else(unauthorized)?;
    Ok(Json(match template_permissions(&app, &user.did).await {
        Ok(perms) => json!({
            "unavailable": false,
            "refusals": perms.into_iter().map(|(t, refusal)| (t.id.clone(), json!(refusal))).collect::<serde_json::Map<_, _>>(),
        }),
        Err(_) => json!({ "unavailable": true, "refusals": {} }),
    }))
}

// ------------------------------------------------------------------ producer: create

async fn templates_list(State(app): State<App>) -> Json<Vec<Template>> {
    Json(app.templates.to_vec())
}

async fn agreements_list(State(app): State<App>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let user = current_user(&app, &headers).await?.ok_or_else(unauthorized)?;
    // Sorted here rather than in the query, so Firestore needs no composite index.
    let mut mine: Vec<Agreement> = app
        .agreements
        .find(doc! { "$or": [ { "producer_did": &user.did }, { "cosigner_email": &user.email } ] })
        .await?
        .try_collect()
        .await?;
    mine.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    let items: Vec<Value> = mine
        .iter()
        .map(|a| {
            let producer = a.producer_did == user.did;
            json!({
                "id": a.id,
                "title": a.title,
                "templateId": a.template_id,
                "assetName": a.asset_name,
                "role": if producer { "producer" } else { "cosigner" },
                "counterparty": if producer { &a.cosigner_email } else { &a.producer_email },
                "stage": a.stage,
                "revoked": a.revoked,
                "createdAt": a.created_at,
            })
        })
        .collect();
    Ok(Json(json!(items)))
}

async fn create_agreement(State(app): State<App>, headers: HeaderMap, mut form: Multipart) -> AppResult<Json<Value>> {
    let user = current_user(&app, &headers).await?.ok_or_else(unauthorized)?;

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
    let tid = values.get("template").and_then(|v| v.first()).cloned().unwrap_or_default();
    let t = app.templates.iter().find(|t| t.id == tid).ok_or_else(|| anyhow!("unknown template"))?.clone();
    // Check 1: before any work, and before the cosigner is asked for anything.
    // Ask about the exact validFrom the credential will carry (whole seconds),
    // since that's the moment the verifier asks about.
    let valid_from = now();
    if let Some(reason) = issue_refusal(&app, &user.did, t.credential_type.as_deref(), Some(&valid_from)).await? {
        return Err(forbidden(&format!(
            "you aren't authorized to issue {} in the trust registry ({reason}); request access at {}",
            t.credential_type.as_deref().unwrap_or_default(),
            request_access_url()
        )));
    }
    if asset.len() < 4 || asset[..3] != [0xff, 0xd8, 0xff] {
        return Err(anyhow!("please upload a JPEG image").into());
    }
    // An optional expiry date: consent lapses at the end of that day (UTC).
    let valid_until = match values.get("valid_until").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(_) if !t.expiry => return Err(anyhow!("this template has no expiry date").into()),
        Some(day) => {
            let until = format!("{day}T23:59:59Z");
            if day.len() != 10 || !day.chars().all(|c| c.is_ascii_digit() || c == '-') || until <= valid_from {
                return Err(anyhow!("choose an expiry date after today").into());
            }
            Some(until)
        }
        None => None,
    };
    // On a license the producer is also the one named in the credential.
    let cosigner_email = if t.self_signed {
        user.email.clone()
    } else {
        values.get("cosigner_email").and_then(|v| v.first()).map(|s| s.trim().to_lowercase()).unwrap_or_default()
    };
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
    let subject = format!("mailto:{cosigner_email}");
    let asset_hash = hard_binding_sha256(&asset, "jpg")?;
    // A guild template gets the guild layer and a status list entry; a bare one neither.
    let authority = registry_authority();
    let (industry, index) = match (&t.credential_type, &t.schema_id) {
        (Some(credential_type), Some(schema_id)) => (
            Some(Industry { credential_type, schema_id, governance_framework: &authority, trust_registry: REGISTRY_URL.get() }),
            Some(next_status_index(&app).await?),
        ),
        _ => (None, None),
    };
    let list_url = status_list_url();
    let credential = build_credential(&CredentialParams {
        issuer_did: &user.did,
        subject_id: &subject,
        asset_hash_b64: &asset_hash,
        consent_domain: if t.self_signed { "asset" } else { "identity" },
        consent: (industry.is_some() || !consent.is_empty()).then(|| Value::Object(consent.clone())),
        industry,
        status: index.map(|index| StatusEntry { list_url: &list_url, index }),
        agreement: &agreement_doc,
        salt: &salt,
        valid_from: &valid_from,
        valid_until: valid_until.as_deref(),
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
            status_index: index.map(|i| i as i64),
            revoked: false,
            self_signed: t.self_signed,
            withdrawal: None,
            stage: Stage::AwaitingProducer,
            error: None,
            signed_key: None,
        })
        .await?;
    Ok(Json(json!({ "id": id })))
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

// ------------------------------------------------------------------ agreement view

#[derive(Deserialize)]
struct InviteQuery {
    invite: Option<String>,
}

enum Viewer {
    Producer,
    /// With the invitation token, which the cosigner's API calls carry.
    Cosigner(String),
    Other,
}

/// The cosigner is whoever has the emailed invitation, or is signed in
/// with a certificate for the email the agreement names.
async fn viewer(app: &App, headers: &HeaderMap, a: &Agreement, invite: Option<&str>) -> AppResult<Viewer> {
    if invite == Some(a.invite_token.as_str()) {
        return Ok(Viewer::Cosigner(a.invite_token.clone()));
    }
    Ok(match current_user(app, headers).await? {
        Some(u) if u.did == a.producer_did => Viewer::Producer,
        Some(u) if u.email == a.cosigner_email => Viewer::Cosigner(a.invite_token.clone()),
        _ => Viewer::Other,
    })
}

async fn agreement_view(
    State(app): State<App>,
    headers: HeaderMap,
    UrlPath(id): UrlPath<String>,
    Query(q): Query<InviteQuery>,
) -> AppResult<Json<Value>> {
    let a = load(&app, &id).await?;
    let (role, invite) = match viewer(&app, &headers, &a, q.invite.as_deref()).await? {
        Viewer::Producer => ("producer", None),
        Viewer::Cosigner(t) => ("cosigner", Some(t)),
        Viewer::Other => return Err(forbidden("only the producer and the person giving consent can open this agreement")),
    };
    // Checks 2 and 3 refuse the next step; say so before anyone opens their wallet.
    // A registry outage doesn't block the page, since the steps check again.
    let blocked = match (role, a.stage) {
        ("producer", Stage::AwaitingProducer) => signing_refusal(&app, &a).await.ok().flatten(),
        (_, Stage::AwaitingCosigner) => issue_refusal(&app, &a.producer_did, governed_type(&a.unsecured()), None).await.ok().flatten(),
        _ => None,
    };
    Ok(Json(json!({
        "id": a.id,
        "title": a.title,
        "templateId": a.template_id,
        "createdAt": a.created_at,
        "role": role,
        "invite": invite,
        "producerEmail": a.producer_email,
        "cosignerEmail": a.cosigner_email,
        "assetName": a.asset_name,
        "assetHash": a.asset_hash,
        "walletAsset": a.wallet_asset(),
        "stage": a.stage,
        "revoked": a.revoked,
        "withdrawable": a.status_index.is_some(),
        "selfSigned": a.self_signed,
        "validUntil": a.unsecured()["validUntil"],
        "withdrawnBy": a.withdrawal.as_deref().and_then(|w| serde_json::from_str::<Withdrawal>(w).ok()).map(|w| w.by),
        // The key this viewer signed the credential with, which a withdrawal must use.
        "signerDid": if role == "producer" { Some(a.producer_did.clone()) } else { a.cosigner_did.clone() },
        "error": a.error,
        "blocked": blocked,
        "producerSigned": a.producer_proof.is_some(),
        "participantSigned": a.participant_proof.is_some(),
        "publicTerms": a.public_terms(),
        "agreementText": a.agreement_text,
        "credential": a.unsecured(),
        "credentialWithProofs": a.credential_with_proofs(),
    })))
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
    if !matches!(viewer(&app, &headers, &a, None).await?, Viewer::Producer) || a.stage != Stage::AwaitingProducer || a.self_signed {
        return Err(forbidden("not waiting for the producer's signature"));
    }
    check_proof(&a, &body.proof)?;
    if did_of_vm(body.proof["verificationMethod"].as_str().unwrap_or_default()) != a.producer_did {
        return Err(anyhow!("the proof must be made by the issuer").into());
    }
    // Check 2: the producer may still issue it, both now and as of validFrom.
    if let Some(reason) = signing_refusal(&app, &a).await? {
        return Err(forbidden(&format!(
            "you aren't authorized to issue this credential in the trust registry ({reason}), so it wasn't sent for consent; request access at {}",
            request_access_url()
        )));
    }
    set(&app, &id, doc! { "producer_proof": body.proof.to_string(), "stage": "awaiting_cosigner" }).await?;
    app.mailer
        .send(
            &a.cosigner_email,
            &format!("{} asks for your consent", a.producer_email),
            &format!(
                "{} asked for your consent on Consent-O-Tron: {} for {}. Review the terms and the file before you decide.",
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
    // Check 3: the producer may have been revoked since signing. Don't record
    // consent or write a file for a credential its issuer can no longer issue.
    if let Some(reason) = issue_refusal(&app, &a.producer_did, governed_type(&a.unsecured()), None).await? {
        return Err(forbidden(&format!(
            "{} is no longer authorized to issue this credential ({reason}), so your consent wasn't recorded and no file was written",
            a.producer_email
        )));
    }
    set(&app, &id, doc! { "participant_proof": body.proof.to_string(), "stage": "authoring" }).await?;

    start_authoring(&app, &id, chain).await?;
    Ok(Json(json!({ "ok": true })))
}

/// Writes the signed file in the background: c2pa-rs builds the manifest
/// and waits for the identity signature from the wallet of whoever is named
/// in the credential (the cosigner, or on a license the producer).
async fn start_authoring(app: &App, id: &str, chain: String) -> AppResult<()> {
    let (app, id) = (app.clone(), id.to_string());
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
    Ok(())
}

#[derive(Deserialize)]
struct LicenseBody {
    #[serde(flatten)]
    login: WalletLogin,
    proof: Value,
}

/// A license has one signer: the producer connects the identity their
/// certificate is for, signs the credential, and then signs the identity
/// assertion while the file is written. Returns the agreement's token, which
/// the identity signature step uses.
async fn license(State(app): State<App>, headers: HeaderMap, UrlPath(id): UrlPath<String>, Json(body): Json<LicenseBody>) -> AppResult<Json<Value>> {
    let a = load(&app, &id).await?;
    if !a.self_signed || !matches!(viewer(&app, &headers, &a, None).await?, Viewer::Producer) || a.stage != Stage::AwaitingProducer {
        return Err(forbidden("not waiting for the license to be signed"));
    }
    let who = check_login(&app, &body.login).await?;
    if who.did != a.producer_did || who.email != a.cosigner_email {
        return Err(anyhow!("sign with the identity you created this license with ({})", a.cosigner_email).into());
    }
    if check_proof(&a, &body.proof)? != resolve_did_key(&who.did)?.to_bytes() {
        return Err(anyhow!("the license must be signed by the identity you connected").into());
    }
    set(
        &app,
        &id,
        doc! { "producer_proof": body.proof.to_string(), "cosigner_did": &who.did, "cosigner_chain_pem": &who.chain_pem, "stage": "authoring" },
    )
    .await?;
    start_authoring(&app, &id, who.chain_pem).await?;
    Ok(Json(json!({ "invite": a.invite_token })))
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

/// What a party signs to withdraw: a fresh challenge, the credential and
/// their own key, so the statement can't be replayed onto another credential.
fn withdrawal_message(challenge: &str, credential_id: &str, did: &str) -> String {
    format!("consent-withdrawal:{}", json!([challenge, credential_id, did]))
}

#[derive(Deserialize)]
struct WithdrawBody {
    challenge: String,
    did: String,
    signature: String,
}

/// Kept on the agreement as evidence of who withdrew.
#[derive(Serialize, Deserialize)]
struct Withdrawal {
    /// "producer" or "cosigner".
    by: String,
    did: String,
    at: String,
    challenge: String,
    signature: String,
}

/// Either party that signed the credential can withdraw it, by signing a
/// withdrawal statement with the key they signed the credential with. Both
/// set the same status list bit.
async fn withdraw(State(app): State<App>, UrlPath(id): UrlPath<String>, Json(body): Json<WithdrawBody>) -> AppResult<Json<Value>> {
    let a = load(&app, &id).await?;
    if a.participant_proof.is_none() {
        return Err(forbidden("consent hasn't been given, so there is nothing to withdraw"));
    }
    if a.revoked {
        return Err(forbidden("consent has already been withdrawn"));
    }
    if a.status_index.is_none() {
        return Err(forbidden("this consent can't be withdrawn: it has no status list entry"));
    }
    let (by, other) = if body.did == a.producer_did {
        ("producer", &a.cosigner_email)
    } else if a.cosigner_did.as_deref() == Some(body.did.as_str()) {
        ("cosigner", &a.producer_email)
    } else {
        return Err(forbidden("only the producer or the person who consented can withdraw"));
    };
    take_challenge(&app, &body.challenge).await?;
    let credential_id = a.unsecured()["id"].as_str().unwrap_or_default().to_string();
    let sig = Signature::from_slice(&STANDARD.decode(&body.signature)?)?;
    resolve_did_key(&body.did)?
        .verify(withdrawal_message(&body.challenge, &credential_id, &body.did).as_bytes(), &sig)
        .map_err(|_| anyhow!("withdrawal signature does not verify"))?;
    let record = Withdrawal { by: by.into(), did: body.did, at: now(), challenge: body.challenge, signature: body.signature };
    set(&app, &id, doc! { "revoked": true, "withdrawal": serde_json::to_string(&record)? }).await?;
    let who = if by == "producer" { &a.producer_email } else { &a.cosigner_email };
    app.mailer
        .send(
            other,
            &format!("{who} withdrew consent"),
            &format!("{who} withdrew the consent for {} on {}. Verifiers that check status now see it as withdrawn.", a.title, a.asset_name),
            &if by == "producer" { format!("{CONSENT_SITE}/a/{id}?invite={}", a.invite_token) } else { format!("{CONSENT_SITE}/a/{id}") },
        )
        .await?;
    Ok(Json(json!({ "ok": true })))
}

fn status_list_url() -> String {
    format!("{CONSENT_SITE}/status/1")
}

async fn signed_status_list(app: &App) -> AppResult<Value> {
    let revoked: Vec<Agreement> = app.agreements.find(doc! { "revoked": true }).await?.try_collect().await?;
    let indices: Vec<usize> = revoked.iter().filter_map(|a| a.status_index).map(|i| i as usize).collect();
    let mut list = build_status_list(&status_list_url(), &did_key(&app.service_key.verifying_key()), &indices)?;
    add_proof(&mut list, &app.service_key, &now())?;
    Ok(list)
}

async fn status_list(State(app): State<App>) -> AppResult<Json<Value>> {
    Ok(Json(signed_status_list(&app).await?))
}

// ------------------------------------------------------------------ issuing permission

/// The trust registry's reason for refusing `did` permission to issue
/// `credential_type` at `time` (None: now), or None if it is authorized. It
/// asks exactly what the verifier asks (verify::check_issuer), so Consent-o-tron
/// refuses up front what verification would reject later.
async fn issue_refusal(app: &App, did: &str, credential_type: Option<&str>, time: Option<&str>) -> AppResult<Option<String>> {
    // A bare credential names no governance framework, so no registry decides.
    let Some(credential_type) = credential_type else { return Ok(None) };
    let mut body = json!({ "entity_id": did, "authority_id": registry_authority(), "action": "issue", "resource": credential_type });
    if let Some(time) = time {
        body["context"] = json!({ "time": time });
    }
    let answer: Value = app
        .http
        .post(format!("{REGISTRY_URL}/authorization"))
        .json(&body)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .context("the trust registry could not be asked")?
        .json()
        .await?;
    match answer["authorized"].as_bool() {
        Some(true) => Ok(None),
        Some(false) => Ok(Some(answer["reason"].as_str().unwrap_or("not_authorized").to_string())),
        None => Err(anyhow!("the trust registry's answer has no authorized field").into()),
    }
}

/// Refused when signing (now) or at the credential's validFrom, the moment
/// the verifier will ask about.
async fn signing_refusal(app: &App, a: &Agreement) -> AppResult<Option<String>> {
    let credential = a.unsecured();
    let ty = governed_type(&credential);
    if let Some(reason) = issue_refusal(app, &a.producer_did, ty, credential["validFrom"].as_str()).await? {
        return Ok(Some(reason));
    }
    issue_refusal(app, &a.producer_did, ty, None).await
}

fn request_access_url() -> String {
    format!("{}/request", REGISTRY_URL.get())
}

/// Each template, with the registry's refusal if this user may not issue it.
async fn template_permissions<'a>(app: &'a App, did: &str) -> AppResult<Vec<(&'a Template, Option<String>)>> {
    let mut out = Vec::new();
    for t in app.templates.iter() {
        out.push((t, issue_refusal(app, did, t.credential_type.as_deref(), None).await?));
    }
    Ok(out)
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

async fn verify_agreement(
    State(app): State<App>,
    headers: HeaderMap,
    UrlPath(id): UrlPath<String>,
    Query(q): Query<VerifyQuery>,
) -> AppResult<Json<Value>> {
    let a = load(&app, &id).await?;
    let party = !matches!(viewer(&app, &headers, &a, q.invite.as_deref()).await?, Viewer::Other);
    let signed = app.blobs.get(a.signed_key.as_deref().ok_or_else(|| anyhow!("not signed yet"))?).await?;
    let revealed = q.reveal.is_some() && party;
    let agreement = if revealed { serde_json::from_str(&a.private_agreement).ok() } else { None };
    let inputs = verify_inputs(&app, q.offline.is_some(), agreement).await?;
    let report: Report = verify_asset(&app.root, "image/jpeg", &signed, &inputs)?;
    Ok(Json(json!({ "assetName": a.asset_name, "title": a.title, "party": party, "revealed": revealed, "report": report })))
}

async fn verify_upload(State(app): State<App>, mut form: Multipart) -> AppResult<Json<Report>> {
    let (mut file, mut offline) = (Vec::new(), false);
    while let Some(field) = form.next_field().await? {
        match field.name() {
            Some("file") => file = field.bytes().await?.to_vec(),
            Some("offline") => offline = true,
            _ => {}
        }
    }
    let inputs = verify_inputs(&app, offline, None).await?;
    Ok(Json(verify_asset(&app.root, "image/jpeg", &file, &inputs)?))
}

async fn outbox(State(app): State<App>) -> AppResult<Json<Value>> {
    Ok(Json(json!({ "resend": app.mailer.uses_resend(), "emails": app.mailer.list().await? })))
}
