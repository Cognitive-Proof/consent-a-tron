//! Verifies the consent credential(s) in a signed asset.
//!
//! cargo run --bin verify -- <signed.jpg> [--offline] [--status <file>]
//!     [--registry <file>] [--agreement <file>]
//!
//! Defaults read status-list.json and trqp-registry.json from the asset's
//! directory. They stand in for fetching the credential's
//! statusListCredential URL and querying its governance framework's TRQP
//! registry. --offline skips both, as a disconnected reader would.
//!
//! Prints one status code per check and exits non-zero unless every
//! credential is cawg.consent.credential.valid.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context as _, Result};
use cawg_consent_test::verify::{verify_asset, Inputs};
use serde_json::Value;

fn main() -> Result<()> {
    let mut it = std::env::args().skip(1);
    let asset = PathBuf::from(it.next().ok_or_else(|| anyhow!("usage: verify <signed.jpg> [options]"))?);
    let dir = asset.parent().unwrap_or(Path::new(".")).to_path_buf();
    let (mut offline, mut status, mut registry, mut agreement) =
        (false, dir.join("status-list.json"), dir.join("trqp-registry.json"), None);
    while let Some(flag) = it.next() {
        let mut value = || it.next().map(PathBuf::from).ok_or_else(|| anyhow!("{flag} needs a value"));
        match flag.as_str() {
            "--offline" => offline = true,
            "--status" => status = value()?,
            "--registry" => registry = value()?,
            "--agreement" => agreement = Some(value()?),
            _ => bail!("unknown option {flag}"),
        }
    }

    let inputs = Inputs {
        registry: if offline { None } else { Some(read_json(&registry)?) },
        status_list: if offline { None } else { Some(read_json(&status)?) },
        agreement: agreement.as_deref().map(read_json).transpose()?,
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let format = c2pa::format_from_path(&asset).unwrap_or_else(|| "image/jpeg".into());
    let report = verify_asset(root, &format, &std::fs::read(&asset)?, &inputs)?;

    println!("C2PA manifest: {}", report.c2pa_state);
    for f in &report.c2pa_failures {
        println!("  failure  {}  {}", f.code, f.url);
    }
    for (i, c) in report.credentials.iter().enumerate() {
        println!("\nCredential {i}: {}", c.id);
        println!("  public terms: {}", c.public_terms);
        for o in &c.outcomes {
            println!("  {} {:<48} {}", if o.pass { "ok  " } else { "FAIL" }, o.code, o.explanation);
        }
        println!("  => cawg.consent.credential.{}", if c.valid { "valid" } else { "invalid" });
    }
    std::process::exit(if report.valid { 0 } else { 1 });
}

fn read_json(path: &Path) -> Result<Value> {
    serde_json::from_str(&std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?)
        .with_context(|| format!("parsing {}", path.display()))
}
