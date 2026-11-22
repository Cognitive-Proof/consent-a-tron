//! Signs an asset with a C2PA manifest carrying the consent credential.
//!
//! cargo run --bin sign -- <asset.jpg> <credential.json> <signed.jpg>
//!
//! The manifest gets:
//!   cawg.consent   created assertion: { "credentials": [ <consent credential> ] }
//!   cawg.identity  signed by the participant's CAWG X.509 credential, with
//!                  cawg.consent (and the hard binding) in referenced_assertions

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use c2pa::{settings::Settings, Builder, BuilderIntent, Context};
use cawg_consent_test::{c2pa_settings_toml, manifest_definition};
use serde_json::Value;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        bail!("usage: sign <asset.jpg> <credential.json> <signed.jpg>");
    }
    let (source, credential, dest) = (PathBuf::from(&args[1]), PathBuf::from(&args[2]), PathBuf::from(&args[3]));
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    let credential: Value = serde_json::from_str(&std::fs::read_to_string(&credential)?)?;
    let manifest = manifest_definition(&[credential], "cawg-consent-test");

    let settings = Settings::new().with_toml(&c2pa_settings_toml(root, true)?)?;
    let context = Context::new().with_settings(settings)?.into_shared();
    let signer = context.signer()?;

    let mut builder = Builder::from_shared_context(&context).with_definition(manifest.to_string().as_str())?;
    builder.set_intent(BuilderIntent::Edit);

    if dest.exists() {
        std::fs::remove_file(&dest)?;
    }
    builder.sign_file(signer, &source, &dest)?;
    println!("wrote {}", dest.display());
    Ok(())
}
