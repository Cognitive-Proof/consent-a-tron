//! Certificate site (http://localhost:4001).
//!
//! email → verify link → Stripe test payment → ID + face upload (discarded)
//! → wallet sends its public key → Ed25519 leaf certificate from the CAWG
//! test CA, with the verified email as its rfc822Name SAN.
//!
//! Also hosts the mock TRQP registry for the guild's governance framework:
//! certified producers are authorized to issue consent credentials, and
//! Consent-o-tron's service key to publish their status lists.
//!
//! State lives in MongoDB (`enrollments`, `trqp_authorizations`, `outbox`).
//!
//! Env (see .env.example): MONGODB_URI, STRIPE_SECRET_KEY (sk_test_… only;
//! without it payment is simulated), RESEND_API_KEY, EMAIL_FROM.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail};
use axum::{
    extract::{DefaultBodyLimit, Multipart, Path as UrlPath, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use cawg_consent_test::{did_key, ed25519_spki_der, load_ed25519_pem, pki, uuid_v4, GOVERNANCE_FRAMEWORK};
use demo_common::{
    esc,
    mongodb::{bson::doc, options::UpdateOptions, Collection},
    Mailer, Site, CERT_SITE,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::TryStreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const SITE: Site = Site { class: "cert", name: "Certificate site" };
const CREDENTIAL_TYPE: &str = "ExampleGuildLikenessConsentCredential";
const PRICE_CENTS: u32 = 500;

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Role {
    Producer,
    Performer,
}

#[derive(Serialize, Deserialize)]
struct Enrollment {
    #[serde(rename = "_id")]
    id: String,
    email_token: Option<String>,
    email: String,
    role: Role,
    verified: bool,
    paid: bool,
    id_checked: bool,
    challenge: String,
    cert_chain_pem: Option<String>,
    did: Option<String>,
}

/// One TRQP authorization: entity may perform action on resource under authority.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
struct Authorization {
    entity_id: String,
    authority_id: String,
    action: String,
    resource: String,
    authorized: bool,
}

#[derive(Clone)]
struct App {
    root: PathBuf,
    enrollments: Collection<Enrollment>,
    registry: Collection<Authorization>,
    mailer: Mailer,
    stripe_key: Option<String>,
    http: reqwest::Client,
}

type AppResult<T> = Result<T, AppError>;

struct AppError(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        Self(e.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, format!("{:#}", self.0)).into_response()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let root = demo_common::app_root()?;
    demo_common::load_dotenv(&root);
    let db = demo_common::database().await?;
    let stripe_key = std::env::var("STRIPE_SECRET_KEY").ok().filter(|k| !k.is_empty());
    if let Some(k) = &stripe_key {
        if !k.starts_with("sk_test_") {
            bail!("STRIPE_SECRET_KEY must be a test-mode key (sk_test_…)");
        }
    }

    let app = App {
        enrollments: db.collection("enrollments"),
        registry: db.collection("trqp_authorizations"),
        mailer: Mailer::new("cert-site", &db),
        root,
        stripe_key,
        http: reqwest::Client::new(),
    };
    // Consent-o-tron's service key may publish status lists for the guild type.
    let service = load_ed25519_pem(&pki(&app.root, "consent-o-tron.key")?)?;
    authorize(&app.registry, &did_key(&service.verifying_key()), "publish-status").await?;

    let router = Router::new()
        .route("/", get(home))
        .route("/enroll", post(enroll))
        .route("/verify/{token}", get(verify_email))
        .route("/enroll/{id}", get(enrollment_page))
        .route("/enroll/{id}/pay", post(pay))
        .route("/enroll/{id}/paid", get(paid))
        .route("/enroll/{id}/identity", post(identity_upload))
        .route("/enroll/{id}/certificate", post(issue_certificate))
        .route("/enroll/{id}/certificate.pem", get(certificate_pem))
        .route("/trqp/registry", get(registry))
        .route("/outbox", get(outbox))
        .route("/static/style.css", get(demo_common::style_css))
        .route("/static/wallet-client.js", get(demo_common::wallet_client_js))
        .layer(DefaultBodyLimit::max(20 * 1024 * 1024))
        .with_state(app.clone());

    println!(
        "Certificate site on {CERT_SITE}  (Stripe: {}, email: {})",
        if app.stripe_key.is_some() { "test mode" } else { "simulated" },
        if app.mailer.uses_resend() { "Resend" } else { "outbox only" }
    );
    let listener = tokio::net::TcpListener::bind(demo_common::listen_addr(4001)).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

// ------------------------------------------------------------------ registry

async fn authorize(registry: &Collection<Authorization>, did: &str, action: &str) -> anyhow::Result<()> {
    let key = doc! { "entity_id": did, "authority_id": GOVERNANCE_FRAMEWORK, "action": action, "resource": CREDENTIAL_TYPE };
    registry
        .update_one(key, doc! { "$set": { "authorized": true } })
        .with_options(UpdateOptions::builder().upsert(true).build())
        .await?;
    Ok(())
}

/// The registry in the shape the verifier's mock TRQP query reads.
async fn registry(State(app): State<App>) -> AppResult<Json<Value>> {
    let entries: Vec<Authorization> = app.registry.find(doc! {}).await?.try_collect().await?;
    Ok(Json(json!({
        "_note": "Mock TRQP registry for the guild governance framework, operated by the Certificate site.",
        "authorizations": entries
    })))
}

async fn outbox(State(app): State<App>) -> AppResult<Html<String>> {
    Ok(app.mailer.outbox_page(&SITE).await?)
}

async fn load(app: &App, id: &str) -> AppResult<Enrollment> {
    Ok(app.enrollments.find_one(doc! { "_id": id }).await?.ok_or_else(|| anyhow!("unknown enrollment"))?)
}

async fn set(app: &App, id: &str, fields: demo_common::mongodb::bson::Document) -> AppResult<()> {
    app.enrollments.update_one(doc! { "_id": id }, doc! { "$set": fields }).await?;
    Ok(())
}

// ------------------------------------------------------------------ steps

const STEPS: [&str; 5] = ["Email", "Verify", "Payment", "ID check", "Certificate"];

fn steps(current: usize) -> String {
    let items: String = STEPS
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let class = if i < current { "done" } else if i == current { "now" } else { "" };
            format!(r#"<li class="{class}">{}{s}</li>"#, if i < current { "✓ " } else { "" })
        })
        .collect();
    format!(r#"<ol class="steps">{items}</ol>"#)
}

async fn home() -> Html<String> {
    SITE.page(
        "Get a signing certificate",
        &format!(
            r#"{}
<p>A certificate ties your wallet's key to your verified email, so your consent can be checked by anyone who sees your files.</p>
<form class="card" method="post" action="/enroll">
  <label>Email<input type="email" name="email" required placeholder="you@example.com" /></label>
  <label>I am a
    <select name="role">
      <option value="performer">Performer: I give consent</option>
      <option value="producer">Producer: I ask for consent</option>
    </select>
  </label>
  <div class="row actions"><button>Continue</button></div>
</form>"#,
            steps(0)
        ),
    )
}

#[derive(Deserialize)]
struct EnrollForm {
    email: String,
    role: Role,
}

async fn enroll(State(app): State<App>, Form(form): Form<EnrollForm>) -> AppResult<Redirect> {
    let email = form.email.trim().to_lowercase();
    if !email.contains('@') || email.contains(char::is_whitespace) {
        return Err(anyhow!("invalid email").into());
    }
    let id = uuid_v4();
    let token = uuid_v4();
    app.enrollments
        .insert_one(Enrollment {
            id: id.clone(),
            email_token: Some(token.clone()),
            email: email.clone(),
            role: form.role,
            verified: false,
            paid: false,
            id_checked: false,
            challenge: uuid_v4(),
            cert_chain_pem: None,
            did: None,
        })
        .await?;
    app.mailer
        .send(&email, "Verify your email", "Confirm this address to continue getting your certificate.", &format!("{CERT_SITE}/verify/{token}"))
        .await?;
    Ok(Redirect::to(&format!("/enroll/{id}")))
}

async fn verify_email(State(app): State<App>, UrlPath(token): UrlPath<String>) -> AppResult<Redirect> {
    // Single use: the token is cleared as the email is marked verified.
    let e = app
        .enrollments
        .find_one_and_update(doc! { "email_token": &token }, doc! { "$set": { "verified": true, "email_token": null } })
        .await?
        .ok_or_else(|| anyhow!("link expired or already used"))?;
    Ok(Redirect::to(&format!("/enroll/{}", e.id)))
}

async fn enrollment_page(State(app): State<App>, UrlPath(id): UrlPath<String>) -> AppResult<Html<String>> {
    let e = load(&app, &id).await?;
    let email = esc(&e.email);
    let body = if !e.verified {
        format!(
            r#"{}<div class="card"><p>We sent a verification link to <strong>{email}</strong>.</p>
<p class="muted">{}</p></div>"#,
            steps(1),
            if app.mailer.uses_resend() {
                r#"Check your inbox. It is also listed under <a href="/outbox">Sent emails</a>."#
            } else {
                r#"Test environment: open <a href="/outbox">Sent emails</a> to find it."#
            }
        )
    } else if !e.paid {
        let mode = if app.stripe_key.is_some() {
            "You'll pay with Stripe in test mode. Use card 4242 4242 4242 4242, any future date, any CVC."
        } else {
            "Stripe isn't configured (no STRIPE_SECRET_KEY), so this payment is simulated."
        };
        format!(
            r#"{}<form class="card" method="post" action="/enroll/{id}/pay">
<p>Certificate for <strong>{email}</strong>: <strong>${}.{:02}</strong></p><p class="muted">{mode}</p>
<div class="row actions"><button>Pay</button></div></form>"#,
            steps(2),
            PRICE_CENTS / 100,
            PRICE_CENTS % 100
        )
    } else if !e.id_checked {
        format!(
            r#"{}<form class="card" method="post" action="/enroll/{id}/identity" enctype="multipart/form-data">
<p>Upload a photo of your ID and a photo of your face.</p>
<p class="notice">Test environment: the images are read and discarded immediately. They are never stored, logged, or checked.</p>
<label>Photo of your ID<input type="file" name="id_document" accept="image/*" required /></label>
<label>Photo of your face<input type="file" name="face" accept="image/*" capture="user" required /></label>
<div class="row actions"><button>Submit</button></div></form>"#,
            steps(3)
        )
    } else if let Some(chain) = &e.cert_chain_pem {
        format!(
            r#"{}<div class="card"><p><span class="badge ok">Issued</span> Your certificate for <strong>{email}</strong> is in your wallet.</p>
<div class="mono muted">{}</div>
<p class="muted">Your private key never left your wallet; only the certificate is shown here.</p>
<div class="row actions"><a class="button secondary" href="/enroll/{id}/certificate.pem">Download certificate</a>
<a class="button" href="{wallet}">Open wallet</a></div></div>
<details class="card"><summary>Certificate (PEM)</summary><pre class="agreement">{}</pre></details>"#,
            steps(5),
            esc(e.did.as_deref().unwrap_or_default()),
            esc(chain),
            wallet = demo_common::WALLET_ORIGIN,
        )
    } else {
        format!(
            r##"{}<div class="card"><p>Identity check passed <span class="badge">test mode</span>.</p>
<p>Now connect your wallet. It creates (or picks) a key and sends only the public key; the private key stays in the wallet.</p>
<div class="row actions"><button id="connect">Connect wallet</button></div><p id="status" class="muted"></p></div>
<script type="module">
import {{ WalletSession, postJson }} from "/static/wallet-client.js";
const status = document.querySelector("#status");
document.querySelector("#connect").onclick = async () => {{
  const wallet = new WalletSession();
  try {{
    await wallet.open();
    status.textContent = "Approve the request in your wallet…";
    const key = await wallet.request("certificate:request", {{ challenge: {challenge}, email: {email_js} }});
    status.textContent = "Issuing certificate…";
    const cert = await postJson("/enroll/{id}/certificate", key);
    await wallet.request("certificate:deliver", cert);
    wallet.close();
    location.reload();
  }} catch (err) {{
    status.textContent = err.message;
    wallet.close();
  }}
}};
</script>"##,
            steps(4),
            challenge = serde_json::to_string(&e.challenge)?,
            email_js = serde_json::to_string(&e.email)?,
        )
    };
    Ok(SITE.page("Get a signing certificate", &body))
}

// ------------------------------------------------------------------ payment

async fn pay(State(app): State<App>, UrlPath(id): UrlPath<String>) -> AppResult<Redirect> {
    let e = load(&app, &id).await?;
    if !e.verified {
        return Err(anyhow!("verify your email first").into());
    }
    let email = e.email;
    let Some(key) = &app.stripe_key else {
        set(&app, &id, doc! { "paid": true }).await?;
        return Ok(Redirect::to(&format!("/enroll/{id}")));
    };
    let session: Value = app
        .http
        .post("https://api.stripe.com/v1/checkout/sessions")
        .bearer_auth(key)
        .form(&[
            ("mode", "payment".to_string()),
            ("customer_email", email),
            ("client_reference_id", id.clone()),
            ("line_items[0][quantity]", "1".into()),
            ("line_items[0][price_data][currency]", "usd".into()),
            ("line_items[0][price_data][unit_amount]", PRICE_CENTS.to_string()),
            ("line_items[0][price_data][product_data][name]", "CAWG signing certificate (test)".into()),
            ("success_url", format!("{CERT_SITE}/enroll/{id}/paid?session_id={{CHECKOUT_SESSION_ID}}")),
            ("cancel_url", format!("{CERT_SITE}/enroll/{id}")),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let url = session["url"].as_str().ok_or_else(|| anyhow!("Stripe returned no checkout URL"))?;
    Ok(Redirect::to(url))
}

#[derive(Deserialize)]
struct PaidQuery {
    session_id: String,
}

/// Stripe redirects here; confirm with Stripe rather than trusting the redirect.
async fn paid(State(app): State<App>, UrlPath(id): UrlPath<String>, Query(q): Query<PaidQuery>) -> AppResult<Redirect> {
    let key = app.stripe_key.as_ref().ok_or_else(|| anyhow!("Stripe is not configured"))?;
    let session: Value = app
        .http
        .get(format!("https://api.stripe.com/v1/checkout/sessions/{}", q.session_id))
        .bearer_auth(key)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if session["payment_status"] != "paid" || session["client_reference_id"] != id.as_str() {
        return Err(anyhow!("payment not completed").into());
    }
    set(&app, &id, doc! { "paid": true }).await?;
    Ok(Redirect::to(&format!("/enroll/{id}")))
}

// ------------------------------------------------------------------ ID check

/// Reads and drops both uploads. Nothing is written or logged: this is a
/// stand-in for an identity-proofing service.
async fn identity_upload(State(app): State<App>, UrlPath(id): UrlPath<String>, mut form: Multipart) -> AppResult<Redirect> {
    let mut seen = Vec::new();
    while let Some(mut field) = form.next_field().await? {
        let name = field.name().unwrap_or_default().to_string();
        let mut bytes = 0usize;
        while let Some(chunk) = field.chunk().await? {
            bytes += chunk.len();
        }
        if bytes > 0 {
            seen.push(name);
        }
    }
    if !(seen.iter().any(|n| n == "id_document") && seen.iter().any(|n| n == "face")) {
        return Err(anyhow!("both images are required").into());
    }
    if !load(&app, &id).await?.paid {
        return Err(anyhow!("payment required first").into());
    }
    set(&app, &id, doc! { "id_checked": true }).await?;
    Ok(Redirect::to(&format!("/enroll/{id}")))
}

// ------------------------------------------------------------------ certificate

#[derive(Deserialize)]
struct KeyProof {
    did: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    signature: String,
}

async fn issue_certificate(State(app): State<App>, UrlPath(id): UrlPath<String>, Json(proof): Json<KeyProof>) -> AppResult<Json<Value>> {
    let e = load(&app, &id).await?;
    if !(e.verified && e.paid && e.id_checked) {
        return Err(anyhow!("finish the earlier steps first").into());
    }
    if e.cert_chain_pem.is_some() {
        return Err(anyhow!("a certificate was already issued for this enrollment").into());
    }
    let (email, role, challenge) = (e.email, e.role, e.challenge);

    // Proof of possession: the wallet signed our challenge with the key.
    let key_bytes: [u8; 32] = STANDARD.decode(&proof.public_key)?.try_into().map_err(|_| anyhow!("bad public key"))?;
    let key = VerifyingKey::from_bytes(&key_bytes)?;
    if did_key(&key) != proof.did {
        return Err(anyhow!("did does not match public key").into());
    }
    let sig = Signature::from_slice(&STANDARD.decode(&proof.signature)?)?;
    key.verify(format!("certificate-request:{challenge}").as_bytes(), &sig)
        .map_err(|_| anyhow!("proof of possession failed"))?;

    let chain = issue(&app.root, &key_bytes, &email)?;
    set(&app, &id, doc! { "cert_chain_pem": &chain, "did": &proof.did }).await?;
    if role == Role::Producer {
        authorize(&app.registry, &proof.did, "issue").await?;
    }
    Ok(Json(json!({ "certChainPem": chain, "email": email, "issuer": "Test CAWG Root" })))
}

/// Ed25519 leaf from the CAWG test CA: rfc822Name SAN = verified email,
/// EKU emailProtection + documentSigning, as in scripts/make-pki.sh.
fn issue(root: &Path, public_key: &[u8; 32], email: &str) -> anyhow::Result<String> {
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
        SanType, SerialNumber, SubjectPublicKeyInfo,
    };
    let ca_pem = pki(root, "cawg-root.pem")?;
    let ca_key = KeyPair::from_pem(&pki(root, "cawg-root.key")?)?;
    let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key)?;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, "US");
    dn.push(DnType::OrganizationName, "Consent Demo");
    dn.push(DnType::CommonName, email);
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::Rfc822Name(email.to_string().try_into()?)];
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages =
        vec![ExtendedKeyUsagePurpose::EmailProtection, ExtendedKeyUsagePurpose::Other(vec![1, 3, 6, 1, 5, 5, 7, 3, 36])];
    params.use_authority_key_identifier_extension = true;
    let mut serial: [u8; 16] = rand::random();
    serial[0] &= 0x7f;
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(5);
    params.not_after = now + time::Duration::days(365);

    let spki = SubjectPublicKeyInfo::from_der(&ed25519_spki_der(public_key))?;
    let leaf = params.signed_by(&spki, &issuer)?;
    Ok(format!("{}{}", leaf.pem(), ca_pem))
}

async fn certificate_pem(State(app): State<App>, UrlPath(id): UrlPath<String>) -> AppResult<Response> {
    let chain = load(&app, &id).await?.cert_chain_pem.ok_or_else(|| anyhow!("no certificate yet"))?;
    Ok((
        [(header::CONTENT_TYPE, "application/x-pem-file"), (header::CONTENT_DISPOSITION, "attachment; filename=\"certificate.chain.pem\"")],
        chain,
    )
        .into_response())
}
