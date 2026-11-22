//! Pieces shared by the Certificate site and Consent-o-tron: page layout,
//! the shared stylesheet, the wallet client, MongoDB, and a mailer
//! that sends through Resend and keeps a dev outbox.

use axum::{
    http::header,
    response::{Html, IntoResponse},
};
use futures_util::TryStreamExt;
use mongodb::{bson::doc, Collection, Database};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub use mongodb;

/// A site's public URL: from an environment variable when deployed, a
/// localhost default otherwise. Formats as the URL, so it can be used
/// directly in `format!("{CERT_SITE}/…")`.
pub struct EnvUrl {
    var: &'static str,
    default: &'static str,
    value: std::sync::OnceLock<String>,
}

impl EnvUrl {
    const fn new(var: &'static str, default: &'static str) -> Self {
        Self { var, default, value: std::sync::OnceLock::new() }
    }

    pub fn get(&self) -> &str {
        self.value.get_or_init(|| {
            // An empty value (e.g. `CONSENT_SITE_URL=` copied from .env.example)
            // counts as unset.
            std::env::var(self.var)
                .ok()
                .map(|v| v.trim().trim_end_matches('/').to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| self.default.into())
        })
    }
}

impl std::fmt::Display for EnvUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.get())
    }
}

pub static WALLET_ORIGIN: EnvUrl = EnvUrl::new("WALLET_URL", "http://localhost:4002");
pub static CERT_SITE: EnvUrl = EnvUrl::new("CERT_SITE_URL", "http://localhost:4001");
pub static CONSENT_SITE: EnvUrl = EnvUrl::new("CONSENT_SITE_URL", "http://localhost:4003");

/// Where to listen: 0.0.0.0:$PORT when PORT is set (Cloud Run), else
/// 127.0.0.1 on the site's local port.
pub fn listen_addr(local_port: u16) -> std::net::SocketAddr {
    match std::env::var("PORT").ok().and_then(|p| p.parse().ok()) {
        Some(port) => ([0, 0, 0, 0], port).into(),
        None => ([127, 0, 0, 1], local_port).into(),
    }
}

/// Directory holding schemas/, templates/ and (locally) pki/: APP_ROOT
/// in a container, the repository root otherwise.
pub fn app_root() -> anyhow::Result<std::path::PathBuf> {
    match std::env::var_os("APP_ROOT") {
        Some(root) => Ok(root.into()),
        None => Ok(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize()?),
    }
}

const STYLE: &str = include_str!("../../../wallet/src/style.css");
const WALLET_CLIENT: &str = include_str!("wallet-client.js");

/// Loads `.env` from the repository root into the environment, without
/// overriding variables that are already set.
pub fn load_dotenv(root: &std::path::Path) {
    let Ok(text) = std::fs::read_to_string(root.join(".env")) else { return };
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        if let Some((k, v)) = line.split_once('=') {
            if std::env::var_os(k.trim()).is_none() {
                std::env::set_var(k.trim(), v.trim());
            }
        }
    }
}

/// MONGODB_URI (default mongodb://localhost:27019), database MONGODB_DB
/// (default consent_demo).
pub async fn database() -> anyhow::Result<Database> {
    let uri = std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27019".into());
    let name = std::env::var("MONGODB_DB").unwrap_or_else(|_| "consent_demo".into());
    let db = mongodb::Client::with_uri_str(&uri).await?.database(&name);
    db.run_command(doc! { "ping": 1 })
        .await
        .map_err(|e| anyhow::anyhow!("cannot reach MongoDB at {uri} ({e}); run `docker compose up -d mongo`"))?;
    Ok(db)
}

/// File storage: a Google Cloud Storage bucket when GCS_BUCKET is set
/// (credentials from Application Default Credentials, e.g. the Cloud Run
/// service account or GOOGLE_APPLICATION_CREDENTIALS), otherwise
/// `data/blobs/` under the repository root.
#[derive(Clone)]
pub struct Blobs {
    store: std::sync::Arc<dyn object_store::ObjectStore>,
    pub description: String,
}

impl Blobs {
    pub fn from_env(root: &std::path::Path) -> anyhow::Result<Self> {
        if let Ok(bucket) = std::env::var("GCS_BUCKET").map(|b| b.trim().to_string()).and_then(|b| if b.is_empty() { Err(std::env::VarError::NotPresent) } else { Ok(b) }) {
            let store = object_store::gcp::GoogleCloudStorageBuilder::from_env().with_bucket_name(&bucket).build()?;
            return Ok(Self { store: std::sync::Arc::new(store), description: format!("gs://{bucket}") });
        }
        let dir = root.join("data/blobs");
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            store: std::sync::Arc::new(object_store::local::LocalFileSystem::new_with_prefix(&dir)?),
            description: dir.display().to_string(),
        })
    }

    pub async fn put(&self, key: &str, bytes: Vec<u8>) -> anyhow::Result<()> {
        use object_store::ObjectStoreExt;
        self.store.put(&object_store::path::Path::from(key), bytes.into()).await?;
        Ok(())
    }

    pub async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        use object_store::ObjectStoreExt;
        Ok(self.store.get(&object_store::path::Path::from(key)).await?.bytes().await?.to_vec())
    }
}

pub fn esc(s: impl AsRef<str>) -> String {
    s.as_ref()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// JSON for embedding inside a `<script>` element.
pub fn script_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".into()).replace("</", "<\\/")
}

pub struct Site {
    pub class: &'static str,
    pub name: &'static str,
}

impl Site {
    pub fn page(&self, title: &str, body: &str) -> Html<String> {
        Html(format!(
            r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{title} · {name}</title><link rel="stylesheet" href="/static/style.css" /></head>
<body class="{class}"><main>
<header><div class="site"><a href="/" style="color:inherit;text-decoration:none">{name}</a></div><h1>{title}</h1></header>
{body}
<p class="muted" style="margin-top:48px;font-size:13px">Test environment · <a href="/outbox">Sent emails</a></p>
</main></body></html>"#,
            title = esc(title),
            name = esc(self.name),
            class = self.class,
        ))
    }
}

pub async fn style_css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css")], STYLE)
}

pub async fn wallet_client_js() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/javascript")], WALLET_CLIENT.replace("__WALLET_ORIGIN__", WALLET_ORIGIN.get()))
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Email {
    pub site: String,
    pub at: String,
    pub to: String,
    pub subject: String,
    pub body: String,
    pub link: String,
    /// "resend", "resend-failed: …", or "outbox-only".
    pub delivery: String,
}

/// Sends through Resend when RESEND_API_KEY is set. Every email is also
/// kept in the `outbox` collection and shown at /outbox, so the demo works
/// without Resend and links can be followed from there.
#[derive(Clone)]
pub struct Mailer {
    site: &'static str,
    from: String,
    resend_key: Option<String>,
    outbox: Collection<Email>,
    http: reqwest::Client,
}

impl Mailer {
    pub fn new(site: &'static str, db: &Database) -> Self {
        Self {
            site,
            from: std::env::var("EMAIL_FROM").unwrap_or_else(|_| "Consent Demo <onboarding@resend.dev>".into()),
            resend_key: std::env::var("RESEND_API_KEY").ok().filter(|k| !k.is_empty()),
            outbox: db.collection("outbox"),
            http: reqwest::Client::new(),
        }
    }

    pub fn uses_resend(&self) -> bool {
        self.resend_key.is_some()
    }

    pub async fn send(&self, to: &str, subject: &str, body: &str, link: &str) -> anyhow::Result<()> {
        let delivery = match &self.resend_key {
            None => "outbox-only".to_string(),
            Some(key) => {
                let html = format!(
                    r#"<p>{}</p><p><a href="{link}">{link}</a></p><p style="color:#888">Consent demo · test environment</p>"#,
                    esc(body),
                    link = esc(link)
                );
                let res = self
                    .http
                    .post("https://api.resend.com/emails")
                    .bearer_auth(key)
                    .json(&json!({ "from": self.from, "to": [to], "subject": subject, "text": format!("{body}\n\n{link}\n"), "html": html }))
                    .send()
                    .await;
                match res {
                    Ok(r) if r.status().is_success() => "resend".into(),
                    Ok(r) => format!("resend-failed: {} {}", r.status(), r.text().await.unwrap_or_default()),
                    Err(e) => format!("resend-failed: {e}"),
                }
            }
        };
        if delivery.starts_with("resend-failed") {
            eprintln!("{delivery} (email kept in outbox)");
        }
        self.outbox
            .insert_one(Email {
                site: self.site.into(),
                at: now_utc(),
                to: to.into(),
                subject: subject.into(),
                body: body.into(),
                link: link.into(),
                delivery,
            })
            .await?;
        Ok(())
    }

    /// Every email this site sent, newest first.
    pub async fn outbox_page(&self, site: &Site) -> anyhow::Result<Html<String>> {
        Ok(site.page("Sent emails", &self.outbox_body().await?))
    }

    /// The outbox list without the page around it, for sites with their own layout.
    pub async fn outbox_body(&self) -> anyhow::Result<String> {
        // Sorted here rather than in the query, so Firestore needs no composite index.
        let mut emails: Vec<Email> = self.outbox.find(doc! { "site": self.site }).await?.try_collect().await?;
        emails.sort_by(|a, b| b.at.cmp(&a.at));
        emails.truncate(50);
        let items: String = emails
            .iter()
            .map(|e| {
                let badge = match e.delivery.as_str() {
                    "resend" => r#"<span class="badge ok">sent via Resend</span>"#.to_string(),
                    "outbox-only" => r#"<span class="badge">outbox only</span>"#.to_string(),
                    other => format!(r#"<span class="badge fail" title="{}">Resend failed</span>"#, esc(other)),
                };
                format!(
                    r#"<article class="card"><div class="row"><strong>{}</strong>{badge}</div>
<div class="muted">To {} · {}</div><p>{}</p><a class="button" href="{}">Open link</a></article>"#,
                    esc(&e.subject),
                    esc(&e.to),
                    esc(&e.at),
                    esc(&e.body),
                    esc(&e.link)
                )
            })
            .collect();
        let mode = if self.uses_resend() {
            "Emails are sent through Resend and also listed here."
        } else {
            "RESEND_API_KEY is not set, so emails are only listed here."
        };
        Ok(format!(r#"<p class="notice">{mode}</p>{}"#, if items.is_empty() { "<p class=\"muted\">No emails yet.</p>".into() } else { items }))
    }
}

pub fn now_utc() -> String {
    // RFC 3339 without pulling in a date crate here.
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, (rem / 60) % 60, rem % 60)
}

/// Howard Hinnant's days-to-civil algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (era * 400 + yoe + i64::from(m <= 2), m, d)
}
