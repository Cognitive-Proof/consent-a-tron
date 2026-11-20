//! Withdraws consent: sets a credential's bit in the status list and
//! re-signs the list as the requester. The embedded credential is untouched.
//!
//! cargo run --bin revoke -- <credential.json> <status-list.json>

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use cawg_consent_test::*;
use serde_json::Value;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        bail!("usage: revoke <credential.json> <status-list.json>");
    }
    let (credential, list_path) = (PathBuf::from(&args[1]), PathBuf::from(&args[2]));
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let requester = load_ed25519(&root.join("pki/requester.key"))?;

    let credential: Value = serde_json::from_str(&std::fs::read_to_string(credential)?)?;
    let index: usize = credential["credentialStatus"]["statusListIndex"]
        .as_str()
        .ok_or_else(|| anyhow!("credential has no statusListIndex"))?
        .parse()?;

    let mut list: Value = serde_json::from_str(&std::fs::read_to_string(&list_path)?)?;
    list["credentialSubject"]["encodedList"] = encode_status_list(&[index])?.into();
    list["validFrom"] = now().into();
    list.as_object_mut().ok_or_else(|| anyhow!("status list is not an object"))?.remove("proof");
    add_proof(&mut list, &requester, &now())?;

    std::fs::write(&list_path, serde_json::to_string_pretty(&list)? + "\n")?;
    println!("revoked index {index} in {}", list_path.display());
    Ok(())
}
