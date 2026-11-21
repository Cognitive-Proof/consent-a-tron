//! Certificate site (http://localhost:4001), branded NotSSL.
//!
//! The home page (/) and /demo are a React app in web/, built to web/dist.
//! The enrollment flow starts at /enroll, modeled on NIST LOA2 / IAL2:
//! email → mailbox link (24 h) → Stripe test payment with the card issuer's
//! address check → name, date of birth and ID number validated against a
//! mock records bureau (/records), ID + face photos discarded → 6-digit
//! enrollment code sent to the email of record → wallet sends its public key
//! → Ed25519 leaf certificate from the CAWG test CA, with the verified email
//! as its rfc822Name SAN.
//!
//! Also hosts the mock TRQP registry for the guild's governance framework,
//! which authorizes Consent-o-tron's service key to publish status lists.
//! A certificate alone doesn't authorize issuing consent credentials: that
//! permission is granted by the guild.
//!
//! State lives in MongoDB (`enrollments`, `identity_records`,
//! `trqp_authorizations`, `outbox`).
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
use cawg_consent_test::{did_key, ed25519_spki_der, load_ed25519_pem, pki, sha256_b64, uuid_v4, GOVERNANCE_FRAMEWORK};
use demo_common::{
    esc,
    mongodb::{bson::doc, options::UpdateOptions, Collection},
    Mailer, CERT_SITE,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::TryStreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower_http::services::{ServeDir, ServeFile};

const CREDENTIAL_TYPE: &str = "ExampleGuildLikenessConsentCredential";
const PRICE_CENTS: u32 = 500;

#[derive(Serialize, Deserialize)]
struct Enrollment {
    #[serde(rename = "_id")]
    id: String,
    email_token: Option<String>,
    email: String,
    /// Unix seconds after which the mailbox link no longer works.
    #[serde(default)]
    email_token_expires: i64,
    verified: bool,
    paid: bool,
    /// The card issuer's address verification (AVS) result, from Stripe.
    #[serde(default)]
    card_checks: Option<CardChecks>,
    /// Identity evidence matched a record at the records bureau.
    id_checked: bool,
    /// The email the bureau holds for this person: the address of record.
    #[serde(default)]
    address_of_record: Option<String>,
    /// SHA-256 of the current enrollment code, sent to the address of record.
    #[serde(default)]
    code_hash: Option<String>,
    #[serde(default)]
    code_expires: i64,
    #[serde(default)]
    code_attempts: u32,
    /// The enrollment code was entered: the address of record is confirmed.
    #[serde(default)]
    address_confirmed: bool,
    challenge: String,
    cert_chain_pem: Option<String>,
    did: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct CardChecks {
    address_line1: String,
    postal_code: String,
}

impl CardChecks {
    fn failed(&self) -> bool {
        self.address_line1 == "fail" || self.postal_code == "fail"
    }
}

/// A person as an identity records bureau knows them. Stands in for the
/// issuer and credit-bureau records a real CA validates evidence against.
#[derive(Serialize, Deserialize)]
struct IdentityRecord {
    /// The government ID number, normalized (see `id_number`).
    #[serde(rename = "_id")]
    id_number: String,
    full_name: String,
    /// YYYY-MM-DD
    date_of_birth: String,
    email: String,
    created_at: String,
}

const DAY: i64 = 24 * 60 * 60;
/// 800-63A: an enrollment code sent to an email of record is valid for 24 hours.
const CODE_TTL: i64 = DAY;
const MAX_CODE_ATTEMPTS: u32 = 5;

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// ID numbers compare without case, spaces or dashes.
fn id_number(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_uppercase()
}

fn same_name(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    norm(a) == norm(b)
}

/// d•••@example.com
fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((user, domain)) => format!("{}•••@{domain}", user.chars().next().unwrap_or('•')),
        None => "•••".into(),
    }
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
    records: Collection<IdentityRecord>,
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
        records: db.collection("identity_records"),
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
        .route("/", get(web_index))
        .route("/demo", get(web_index))
        .nest_service("/assets", ServeDir::new(web_dist(&app.root).join("assets")))
        .route_service("/logo.svg", ServeFile::new(web_dist(&app.root).join("logo.svg")))
        .route("/enroll", get(enroll_start).post(enroll))
        .route("/verify/{token}", get(verify_email))
        .route("/enroll/{id}", get(enrollment_page))
        .route("/enroll/{id}/pay", post(pay))
        .route("/enroll/{id}/paid", get(paid))
        .route("/enroll/{id}/identity", post(identity_upload))
        .route("/enroll/{id}/code", post(confirm_code))
        .route("/enroll/{id}/code/resend", post(resend_code))
        .route("/enroll/{id}/certificate", post(issue_certificate))
        .route("/enroll/{id}/certificate.pem", get(certificate_pem))
        .route("/trqp/registry", get(registry))
        .route("/records", get(records_page).post(create_record))
        .route("/outbox", get(outbox))
        .route("/static/notssl.css", get(style_css))
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
    let body = app.mailer.outbox_body().await?;
    Ok(page("Sent emails", &format!(r#"{}<div class="wrap layout single"><div>{body}</div></div>"#, band("NotSSL", "Sent emails", None))))
}

async fn load(app: &App, id: &str) -> AppResult<Enrollment> {
    Ok(app.enrollments.find_one(doc! { "_id": id }).await?.ok_or_else(|| anyhow!("unknown enrollment"))?)
}

async fn set(app: &App, id: &str, fields: demo_common::mongodb::bson::Document) -> AppResult<()> {
    app.enrollments.update_one(doc! { "_id": id }, doc! { "$set": fields }).await?;
    Ok(())
}

// ------------------------------------------------------------------ steps

const STEPS: [&str; 6] = ["Email", "Verify", "Payment", "Identity", "Code", "Certificate"];
const STYLE: &str = include_str!("notssl.css");

async fn style_css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], STYLE)
}

fn web_dist(root: &Path) -> PathBuf {
    root.join("crates/cert-site/web/dist")
}

/// The React app's page; it picks home or the demo page from the path.
async fn web_index(State(app): State<App>) -> AppResult<Html<String>> {
    let path = web_dist(&app.root).join("index.html");
    let html = tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| anyhow!("{}: {e} (run `npm run build` in crates/cert-site/web)", path.display()))?;
    Ok(Html(html))
}

/// The NotSSL frame around every server-rendered page: the same top bar,
/// nav and footer as the React home page.
fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{title} · NotSSL</title><link rel="icon" type="image/svg+xml" href="/logo.svg" /><link rel="stylesheet" href="/static/notssl.css" /></head>
<body>
<div class="topbar"><div class="wrap"><strong>Demonstration site.</strong> NotSSL is not a real certificate authority; certificates come from the CAWG test CA.</div></div>
<header class="nav"><div class="wrap"><a class="brand" href="/"><img src="/logo.svg" alt="" />NotSSL</a>
<span class="nav-help">Need help? <a href="/demo">Contact support</a></span></div></header>
{body}
<footer class="footer"><div class="wrap"><span>© NotSSL. Demonstration only.</span>
<nav><a href="/demo">Privacy</a><a href="/demo">Terms</a><a href="/records">Records bureau</a><a href="/outbox">Sent emails</a></nav></div></footer>
</body></html>"#,
        title = esc(title),
    ))
}

/// A navy band with the page title, and the stepper when `current` is set.
fn band(eyebrow: &str, title: &str, current: Option<usize>) -> String {
    let stepper = current.map_or(String::new(), |current| {
        let items: String = STEPS
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let (class, mark) = if i < current {
                    ("done", "✓".to_string())
                } else if i == current {
                    ("now", (i + 1).to_string())
                } else {
                    ("", (i + 1).to_string())
                };
                format!(r#"<li class="{class}"><span class="dot">{mark}</span>{s}</li>"#)
            })
            .collect();
        format!(r#"<ol class="stepper">{items}</ol>"#)
    });
    format!(r#"<section class="band"><div class="wrap"><span class="eyebrow">{eyebrow}</span><h1>{title}</h1>{stepper}</div></section>"#)
}

/// The LOA2 checks so far, for the order summary.
fn check_list(e: Option<&Enrollment>) -> String {
    let card = match e {
        Some(Enrollment { card_checks: Some(c), .. }) if c.failed() => ("fail", "Card address check failed".to_string()),
        Some(Enrollment { card_checks: Some(c), paid: true, .. }) => {
            ("done", format!("Card address check: {}", if c.address_line1 == "pass" && c.postal_code == "pass" { "pass" } else { "unchecked" }))
        }
        Some(Enrollment { paid: true, .. }) => ("done", "Card address check (simulated)".into()),
        _ => ("", "Card address check".into()),
    };
    let state = |ok: bool| if ok { "done" } else { "" };
    let items = [
        (state(e.is_some_and(|e| e.verified)), "Mailbox control".to_string()),
        card,
        (state(e.is_some_and(|e| e.id_checked)), "ID matched to records".into()),
        (state(e.is_some_and(|e| e.address_confirmed)), "Address of record confirmed".into()),
        (state(e.is_some_and(|e| e.cert_chain_pem.is_some())), "Key stays in your wallet".into()),
    ];
    let lis: String = items.iter().map(|(class, text)| format!(r#"<li class="{class}">{text}</li>"#)).collect();
    format!(r#"<ul class="checks progress">{lis}</ul>"#)
}

/// One enrollment step: the band, the step's card, and the order summary.
fn enroll_page(current: usize, main: &str, e: Option<&Enrollment>) -> Html<String> {
    let product = "LOA2 CAWG Certificate";
    let email = e.map_or(String::new(), |e| format!("<dt>Subject</dt><dd>{}</dd>", esc(&e.email)));
    let price = format!("${}.{:02}", PRICE_CENTS / 100, PRICE_CENTS % 100);
    let title = if current == STEPS.len() { "Your certificate is ready" } else { "Get your LOA2 CAWG certificate" };
    page(
        title,
        &format!(
            r#"{band}
<div class="wrap layout"><div>{main}</div>
<aside class="card summary"><h3>Order summary</h3>
<div class="product"><img src="/logo.svg" alt="" /><div><strong>{product}</strong><span class="muted small">1 year · Ed25519</span></div></div>
<dl class="lines">{email}<dt>Assurance</dt><dd>LOA2</dd><dt>Issuer</dt><dd>CAWG Test CA</dd></dl>
<div class="total"><span>Total</span><span>{price}</span></div>
<h3 class="checks-title">LOA2 checks</h3>{checks}
<p class="help">Questions? <a href="/demo">Talk to an expert</a></p></aside></div>"#,
            band = band("NotSSL enrollment", title, Some(current)),
            checks = check_list(e),
        ),
    )
}

async fn enroll_start() -> Html<String> {
    enroll_page(
        0,
        r#"<form class="card" method="post" action="/enroll">
<h2>Who is this certificate for?</h2>
<p class="lead">A certificate ties your wallet's key to your verified email, so your consent can be checked by anyone who sees your files.</p>
<label for="email">Email address</label>
<input id="email" type="email" name="email" required placeholder="you@example.com" autocomplete="email" />
<div class="actions"><button>Continue</button></div>
</form>"#,
        None,
    )
}

#[derive(Deserialize)]
struct EnrollForm {
    email: String,
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
            email_token_expires: now_secs() + DAY,
            email: email.clone(),
            verified: false,
            paid: false,
            card_checks: None,
            id_checked: false,
            address_of_record: None,
            code_hash: None,
            code_expires: 0,
            code_attempts: 0,
            address_confirmed: false,
            challenge: uuid_v4(),
            cert_chain_pem: None,
            did: None,
        })
        .await?;
    app.mailer
        .send(
            &email,
            "Verify your email",
            "Confirm you control this mailbox to continue getting your certificate. The link works once, for 24 hours.",
            &format!("{CERT_SITE}/verify/{token}"),
        )
        .await?;
    Ok(Redirect::to(&format!("/enroll/{id}")))
}

/// Mailbox validation: proves control of the email that goes in the
/// certificate. Address-of-record confirmation comes later, after the
/// identity check.
async fn verify_email(State(app): State<App>, UrlPath(token): UrlPath<String>) -> AppResult<Redirect> {
    // Single use: the token is cleared as the email is marked verified.
    let e = app
        .enrollments
        .find_one_and_update(doc! { "email_token": &token }, doc! { "$set": { "email_token": null } })
        .await?
        .ok_or_else(|| anyhow!("link expired or already used"))?;
    // Enrollments from before links expired have no expiry (0).
    if e.email_token_expires != 0 && now_secs() > e.email_token_expires {
        return Err(anyhow!("this link expired; start again at {CERT_SITE}/enroll").into());
    }
    set(&app, &e.id, doc! { "verified": true }).await?;
    Ok(Redirect::to(&format!("/enroll/{}", e.id)))
}

async fn enrollment_page(State(app): State<App>, UrlPath(id): UrlPath<String>) -> AppResult<Html<String>> {
    render(&app, &load(&app, &id).await?, None)
}

/// The page for wherever this enrollment is, with an optional error from
/// the step that was just tried.
fn render(app: &App, e: &Enrollment, error: Option<&str>) -> AppResult<Html<String>> {
    let id = &e.id;
    let email = esc(&e.email);
    let card_error = e
        .card_checks
        .as_ref()
        .filter(|c| c.failed() && !e.paid)
        .map(|c| {
            format!(
                "Your card issuer couldn't confirm your billing address (street: {}, postal code: {}). LOA2 needs the financial account to check out, so we stop here; a real CA would refund you. Try again with a card whose address checks pass.",
                esc(&c.address_line1),
                esc(&c.postal_code)
            )
        });
    let error = error.map(esc).or(card_error).map_or(String::new(), |m| format!(r#"<p class="notice error">{m}</p>"#));
    let (current, main) = if !e.verified {
        let where_ = if app.mailer.uses_resend() {
            r#"Check your inbox. It's also listed under <a href="/outbox">Sent emails</a>."#
        } else {
            r#"Test environment: open <a href="/outbox">Sent emails</a> to find it."#
        };
        (
            1,
            format!(
                r#"<div class="card"><div class="big-icon">✉️</div><h2>Check your inbox</h2>
<p class="lead">We sent a link to <strong>{email}</strong> to prove you control this mailbox. It works once, for 24 hours.</p>
<p class="notice test">{where_}</p>
<p class="muted small">Wrong address? <a href="/enroll">Start over</a></p></div>"#
            ),
        )
    } else if !e.paid {
        let mode = if app.stripe_key.is_some() {
            "Stripe test mode. Your card issuer checks the billing address you enter (AVS). Use 4242 4242 4242 4242 to pass, or 4000 0000 0000 0010 to see the address check fail. Any future date, any CVC."
        } else {
            "Stripe isn't configured (no STRIPE_SECRET_KEY), so this payment and its card address check are simulated."
        };
        (
            2,
            format!(
                r#"<form class="card" method="post" action="/enroll/{id}/pay"><h2>Payment</h2>
<p class="lead">Your mailbox <strong>{email}</strong> is verified. One payment covers a year, and your card issuer confirms your billing address.</p>
{error}<p class="notice test">{mode}</p>
<div class="actions"><button>Pay ${}.{:02}</button></div></form>"#,
                PRICE_CENTS / 100,
                PRICE_CENTS % 100
            ),
        )
    } else if !e.id_checked {
        (
            3,
            format!(
                r#"<form class="card" method="post" action="/enroll/{id}/identity" enctype="multipart/form-data"><h2>Check your identity</h2>
<p class="lead">We validate your government ID against records, and the email held there becomes your address of record.</p>
{error}
<label for="full_name">Full legal name</label><input id="full_name" type="text" name="full_name" required autocomplete="name" />
<div class="two"><div><label for="date_of_birth">Date of birth</label><input id="date_of_birth" type="date" name="date_of_birth" required /></div>
<div><label for="id_number">ID number</label><input id="id_number" type="text" name="id_number" required placeholder="Driver's license or passport" /></div></div>
<div class="uploads">
<label class="upload"><span class="icon">🪪</span><strong>Photo of your ID</strong><input type="file" name="id_document" accept="image/*" required /></label>
<label class="upload"><span class="icon">🙂</span><strong>Photo of your face</strong><input type="file" name="face" accept="image/*" capture="user" required /></label>
</div>
<p class="notice test">Test environment: details are checked against the <a href="/records?email={email_q}&amp;next=/enroll/{id}">Mock records bureau</a>, where you can create a made-up record first. The images are read and discarded immediately; they are never stored, logged, or checked.</p>
<div class="actions"><button>Check my identity</button></div></form>"#,
                email_q = esc(&url_escape(&e.email)),
            ),
        )
    } else if !e.address_confirmed {
        let to = mask_email(e.address_of_record.as_deref().unwrap_or_default());
        let live = e.code_hash.is_some() && now_secs() <= e.code_expires && e.code_attempts < MAX_CODE_ATTEMPTS;
        let body = if live {
            format!(
                r#"<p class="lead">We sent a 6-digit enrollment code to your address of record, <strong>{to}</strong>. It expires 24 hours after it was sent.</p>
{error}<form method="post" action="/enroll/{id}/code">
<label for="code">Enrollment code</label><input id="code" class="code" type="text" name="code" inputmode="numeric" pattern="[0-9]{{6}}" maxlength="6" autocomplete="one-time-code" required />
<div class="actions"><button>Confirm</button></div></form>
<form method="post" action="/enroll/{id}/code/resend" class="inline"><span class="muted small">Didn't get it?</span><button class="link">Send a new code</button></form>"#
            )
        } else {
            format!(
                r#"<p class="lead">Your enrollment code for <strong>{to}</strong> has expired or was tried too many times.</p>
{error}<form method="post" action="/enroll/{id}/code/resend"><div class="actions"><button>Send a new code</button></div></form>"#
            )
        };
        let where_ = if app.mailer.uses_resend() { "" } else { r#"<p class="notice test">Test environment: the code is in <a href="/outbox">Sent emails</a>.</p>"# };
        (
            4,
            format!(
                r#"<div class="card"><div class="big-icon ok">✓</div><h2>Identity matched. Confirm your address of record</h2>
{body}{where_}</div>"#
            ),
        )
    } else if let Some(chain) = &e.cert_chain_pem {
        (
            6,
            format!(
                r#"<div class="card"><div class="big-icon ok">✓</div><h2>Certificate issued</h2>
<p class="lead">Your certificate for <strong>{email}</strong> is in your wallet.</p>
<div class="cert-card"><div class="cert-head"><span class="brand"><img src="/logo.svg" alt="" />NotSSL</span><span class="cert-level">LOA2</span></div>
<div class="cert-title">CAWG Identity Certificate</div>
<dl class="cert-fields"><dt>Subject</dt><dd>mailto:{email}</dd><dt>Key</dt><dd>{did}</dd><dt>Issuer</dt><dd>CAWG Test CA</dd><dt>Valid</dt><dd>1 year</dd></dl>
<div class="cert-foot">● Verified identity</div></div>
<p class="muted small">Your private key never left your wallet; only the certificate is shown here.</p>
<div class="actions"><a class="button secondary" href="/enroll/{id}/certificate.pem">Download certificate</a><a class="button" href="{wallet}">Open wallet</a></div>
<details class="pem"><summary>Certificate chain (PEM)</summary><pre class="agreement">{pem}</pre></details></div>"#,
                did = esc(e.did.as_deref().unwrap_or_default()),
                pem = esc(chain),
                wallet = demo_common::WALLET_ORIGIN,
            ),
        )
    } else {
        (
            5,
            format!(
                r##"<div class="card"><div class="big-icon ok">✓</div><h2>Address confirmed. Connect your wallet</h2>
<p class="lead">Your wallet creates (or picks) a key and sends us only the public key. The private key never leaves it.</p>
<ul class="bullets"><li><strong>Approve</strong> the request in the wallet window.</li><li>We <strong>sign</strong> your certificate with the CAWG test CA.</li><li>It's <strong>delivered</strong> straight back into your wallet.</li></ul>
<div class="actions"><button id="connect">Connect wallet</button></div><p id="status" class="status"></p></div>
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
                challenge = serde_json::to_string(&e.challenge)?,
                email_js = serde_json::to_string(&e.email)?,
            ),
        )
    };
    Ok(enroll_page(current, &main, Some(e)))
}

/// Percent-encodes a query parameter value.
fn url_escape(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
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
            // The card issuer checks the billing address (AVS); see `paid`.
            ("billing_address_collection", "required".into()),
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

/// Stripe redirects here; confirm with Stripe rather than trusting the
/// redirect, and read the card issuer's address check from the charge.
async fn paid(State(app): State<App>, UrlPath(id): UrlPath<String>, Query(q): Query<PaidQuery>) -> AppResult<Redirect> {
    let key = app.stripe_key.as_ref().ok_or_else(|| anyhow!("Stripe is not configured"))?;
    let session: Value = app
        .http
        .get(format!("https://api.stripe.com/v1/checkout/sessions/{}?expand%5B%5D=payment_intent.latest_charge", url_escape(&q.session_id)))
        .bearer_auth(key)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if session["payment_status"] != "paid" || session["client_reference_id"] != id.as_str() {
        return Err(anyhow!("payment not completed").into());
    }
    let checks = &session["payment_intent"]["latest_charge"]["payment_method_details"]["card"]["checks"];
    let result = |field: &str| checks[field].as_str().unwrap_or("unavailable").to_string();
    let checks = CardChecks { address_line1: result("address_line1_check"), postal_code: result("address_postal_code_check") };
    // A failed address check stops here: the page explains, and paying
    // again with another card replaces the result.
    let paid = !checks.failed();
    set(&app, &id, doc! { "paid": paid, "card_checks": demo_common::mongodb::bson::to_bson(&checks)? }).await?;
    Ok(Redirect::to(&format!("/enroll/{id}")))
}

// ------------------------------------------------------------------ ID check

/// Validates the claimed identity against the records bureau, the way a CA
/// checks an ID number with its issuer, and takes the address of record
/// from the record. The images are read and dropped; nothing is written or
/// logged, as a stand-in for a document and face check.
async fn identity_upload(State(app): State<App>, UrlPath(id): UrlPath<String>, mut form: Multipart) -> AppResult<Response> {
    let (mut full_name, mut date_of_birth, mut number) = (String::new(), String::new(), String::new());
    let mut images = Vec::new();
    while let Some(mut field) = form.next_field().await? {
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "full_name" => full_name = field.text().await?,
            "date_of_birth" => date_of_birth = field.text().await?,
            "id_number" => number = field.text().await?,
            _ => {
                let mut bytes = 0usize;
                while let Some(chunk) = field.chunk().await? {
                    bytes += chunk.len();
                }
                if bytes > 0 {
                    images.push(name);
                }
            }
        }
    }
    let e = load(&app, &id).await?;
    if !e.paid || e.id_checked {
        return Ok(Redirect::to(&format!("/enroll/{id}")).into_response());
    }
    if !(images.iter().any(|n| n == "id_document") && images.iter().any(|n| n == "face")) {
        return Ok(render(&app, &e, Some("Both photos are required."))?.into_response());
    }
    let record = app.records.find_one(doc! { "_id": id_number(&number) }).await?;
    let Some(record) = record.filter(|r| same_name(&r.full_name, &full_name) && r.date_of_birth == date_of_birth.trim()) else {
        return Ok(render(&app, &e, Some("No record matches that ID number, name and date of birth."))?.into_response());
    };
    if record.email != e.email {
        let msg = format!(
            "The email on record for this identity isn't {}. The certificate's email must be your email of record.",
            e.email
        );
        return Ok(render(&app, &e, Some(&msg))?.into_response());
    }
    set(&app, &id, doc! { "id_checked": true, "address_of_record": &record.email }).await?;
    send_code(&app, &id, &record.email).await?;
    Ok(Redirect::to(&format!("/enroll/{id}")).into_response())
}

// ------------------------------------------------------------------ address of record

/// Sends a fresh 6-digit enrollment code to the address of record. Only
/// its salted hash is stored.
async fn send_code(app: &App, id: &str, address: &str) -> AppResult<()> {
    let code = format!("{:06}", rand::Rng::gen_range(&mut rand::thread_rng(), 0..1_000_000u32));
    let hash = sha256_b64(format!("{id}:{code}").as_bytes());
    set(app, id, doc! { "code_hash": hash, "code_expires": now_secs() + CODE_TTL, "code_attempts": 0 }).await?;
    app.mailer
        .send(
            address,
            "Your NotSSL enrollment code",
            &format!("Your enrollment code is {code}. Enter it on the enrollment page to confirm this is your address of record. It expires in 24 hours."),
            &format!("{CERT_SITE}/enroll/{id}"),
        )
        .await?;
    Ok(())
}

async fn resend_code(State(app): State<App>, UrlPath(id): UrlPath<String>) -> AppResult<Redirect> {
    let e = load(&app, &id).await?;
    if let (true, false, Some(address)) = (e.id_checked, e.address_confirmed, &e.address_of_record) {
        send_code(&app, &id, address).await?;
    }
    Ok(Redirect::to(&format!("/enroll/{id}")))
}

#[derive(Deserialize)]
struct CodeForm {
    code: String,
}

async fn confirm_code(State(app): State<App>, UrlPath(id): UrlPath<String>, Form(form): Form<CodeForm>) -> AppResult<Response> {
    let e = load(&app, &id).await?;
    let Some(hash) = e.code_hash.as_ref().filter(|_| e.id_checked && !e.address_confirmed) else {
        return Ok(Redirect::to(&format!("/enroll/{id}")).into_response());
    };
    if now_secs() > e.code_expires || e.code_attempts >= MAX_CODE_ATTEMPTS {
        return Ok(render(&app, &e, Some("That code has expired. Send a new one."))?.into_response());
    }
    if sha256_b64(format!("{id}:{}", form.code.trim()).as_bytes()) == *hash {
        set(&app, &id, doc! { "address_confirmed": true, "code_hash": null }).await?;
        return Ok(Redirect::to(&format!("/enroll/{id}")).into_response());
    }
    app.enrollments.update_one(doc! { "_id": &id }, doc! { "$inc": { "code_attempts": 1 } }).await?;
    let e = load(&app, &id).await?;
    let left = MAX_CODE_ATTEMPTS.saturating_sub(e.code_attempts);
    let msg = format!("That code isn't right. {left} attempt{} left.", if left == 1 { "" } else { "s" });
    Ok(render(&app, &e, Some(&msg))?.into_response())
}

// ------------------------------------------------------------------ records bureau

#[derive(Deserialize)]
struct RecordsQuery {
    email: Option<String>,
    next: Option<String>,
}

/// The mock records bureau: testers create made-up people here, and the ID
/// check validates against them.
async fn records_page(State(app): State<App>, Query(q): Query<RecordsQuery>) -> AppResult<Html<String>> {
    let mut records: Vec<IdentityRecord> = app.records.find(doc! {}).await?.try_collect().await?;
    records.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    records.truncate(50);
    let rows: String = records
        .iter()
        .map(|r| {
            format!(
                "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&r.id_number),
                esc(&r.full_name),
                esc(&r.date_of_birth),
                esc(&r.email)
            )
        })
        .collect();
    let table = if rows.is_empty() {
        r#"<p class="muted">No records yet.</p>"#.to_string()
    } else {
        format!(r#"<div class="table"><table><thead><tr><th>ID number</th><th>Name</th><th>Date of birth</th><th>Email of record</th></tr></thead><tbody>{rows}</tbody></table></div>"#)
    };
    let next = q.next.filter(|n| n.starts_with("/enroll/")).unwrap_or_default();
    let back = if next.is_empty() { String::new() } else { format!(r#"<p class="small"><a href="{}">← Back to your enrollment</a></p>"#, esc(&next)) };
    Ok(page(
        "Mock records bureau",
        &format!(
            r#"{band}<div class="wrap layout single"><div>
<div class="card"><h2>Create a record</h2>
<p class="lead">A real CA validates your ID number with its issuer and credit-bureau records, and takes your address of record from them. This mock bureau plays that part so the demo doesn't pay for verification.</p>
<p class="notice test">Use made-up details only. Every record is visible to anyone using this demo.</p>
<form method="post" action="/records"><input type="hidden" name="next" value="{next}" />
<label for="full_name">Full legal name</label><input id="full_name" type="text" name="full_name" required />
<div class="two"><div><label for="date_of_birth">Date of birth</label><input id="date_of_birth" type="date" name="date_of_birth" required /></div>
<div><label for="id_number">ID number</label><input id="id_number" type="text" name="id_number" required placeholder="D1234567" /></div></div>
<label for="email">Email of record</label><input id="email" type="email" name="email" required value="{email}" />
<div class="actions"><button>Create record</button></div></form>{back}</div>
<div class="card"><h2>Records</h2>{table}</div></div></div>"#,
            band = band("Test environment", "Mock records bureau", None),
            next = esc(&next),
            email = esc(q.email.unwrap_or_default()),
        ),
    ))
}

#[derive(Deserialize)]
struct RecordForm {
    full_name: String,
    date_of_birth: String,
    id_number: String,
    email: String,
    #[serde(default)]
    next: String,
}

async fn create_record(State(app): State<App>, Form(form): Form<RecordForm>) -> AppResult<Redirect> {
    let number = id_number(&form.id_number);
    let email = form.email.trim().to_lowercase();
    if number.is_empty() || form.full_name.trim().is_empty() || form.date_of_birth.trim().is_empty() || !email.contains('@') {
        return Err(anyhow!("every field is required").into());
    }
    if app.records.find_one(doc! { "_id": &number }).await?.is_some() {
        return Err(anyhow!("a record with ID number {number} already exists").into());
    }
    app.records
        .insert_one(IdentityRecord {
            id_number: number,
            full_name: form.full_name.split_whitespace().collect::<Vec<_>>().join(" "),
            date_of_birth: form.date_of_birth.trim().to_string(),
            email,
            created_at: demo_common::now_utc(),
        })
        .await?;
    let next = if form.next.starts_with("/enroll/") { form.next } else { "/records".into() };
    Ok(Redirect::to(&next))
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
    if !(e.verified && e.paid && e.id_checked && e.address_confirmed) {
        return Err(anyhow!("finish the earlier steps first").into());
    }
    if e.cert_chain_pem.is_some() {
        return Err(anyhow!("a certificate was already issued for this enrollment").into());
    }
    let (email, challenge) = (e.email, e.challenge);

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
