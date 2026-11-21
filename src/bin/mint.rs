//! Mints a consent credential for an asset, before the C2PA manifest exists.
//!
//! cargo run --bin mint -- <asset.jpg> <out-dir>
//!
//! Writes:
//!   credential.json         the consent credential (requester + participant proofs)
//!   private-agreement.json  the private terms and salt; held by the parties, never embedded
//!   status-list.json        mock Bitstring Status List credential (all active)
//!   trqp-registry.json      mock TRQP registry authorizing the requester

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use cawg_consent_test::*;
use rand::RngCore;
use serde_json::{json, Value};

const STATUS_LIST_URL: &str = "https://status.guild.example/consent/lists/1";
const CREDENTIAL_TYPE: &str = "ExampleGuildLikenessConsentCredential";
const STATUS_INDEX: usize = 4_242;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        bail!("usage: mint <asset.jpg> <out-dir>");
    }
    let asset = PathBuf::from(&args[1]);
    let out = PathBuf::from(&args[2]);
    std::fs::create_dir_all(&out)?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    let requester = load_ed25519(&root.join("pki/requester.key"))?;
    // MINT_PARTICIPANT_KEY lets the test cases mint for someone other than
    // the identity assertion signer.
    let participant_key = std::env::var_os("MINT_PARTICIPANT_KEY")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("pki/participant.key"));
    let participant = load_ed25519(&participant_key)?;
    let requester_did = did_key(&requester.verifying_key());
    let participant_did = did_key(&participant.verifying_key());

    // The C2PA data hash excludes the manifest store, so hash the asset as
    // it will be once any existing manifest is replaced.
    let ext = asset.extension().and_then(|e| e.to_str()).unwrap_or("jpg").to_lowercase();
    let asset_hash = hard_binding_sha256(&std::fs::read(&asset)?, &ext)?;

    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    let agreement = json!({
        "engagement": "Spring campaign stills, shoot of 2026-11-18",
        "fee": { "amount": "1500.00", "currency": "USD" },
        "contract": "urn:example:contract:2026-0117",
        "signedBy": [requester_did, participant_did]
    });
    let created = now();

    let mut credential = build_credential(&CredentialParams {
        issuer_did: &requester_did,
        subject_id: &participant_did,
        asset_hash_b64: &asset_hash,
        credential_type: CREDENTIAL_TYPE,
        industry_schema_id: GUILD_SCHEMA_ID,
        status_list_url: STATUS_LIST_URL,
        status_index: STATUS_INDEX,
        governance_framework: GOVERNANCE_FRAMEWORK,
        trust_registry: TRUST_REGISTRY,
        consent: json!({
            "aspects": ["image", "likeness"],
            "permittedUses": ["editorial", "promotional"],
            "aiTraining": "notAllowed",
            "digitalReplica": "notAllowed",
            "territory": "WORLD"
        }),
        agreement: &agreement,
        salt: &salt,
        valid_from: &created,
    })?;

    // Proof set: the requester signs as issuer, then the participant cosigns.
    add_proof(&mut credential, &requester, &created)?;
    add_proof(&mut credential, &participant, &created)?;

    let errors = validate_schema(&root.join("schemas"), &credential)?;
    if !errors.is_empty() {
        bail!("credential does not match schema:\n  {}", errors.join("\n  "));
    }

    let mut status_list = build_status_list(STATUS_LIST_URL, &requester_did, &[])?;
    add_proof(&mut status_list, &requester, &created)?;

    let authorize = |action: &str| {
        json!({
            "entity_id": requester_did,
            "authority_id": GOVERNANCE_FRAMEWORK,
            "action": action,
            "resource": CREDENTIAL_TYPE,
            "authorized": true
        })
    };
    let registry = json!({
        "_note": "Mock TRQP trust registry. In practice the guild operates this under its governance framework.",
        "authorizations": [authorize("issue"), authorize("publish-status")]
    });

    write(&out.join("credential.json"), &credential)?;
    write(&out.join("private-agreement.json"), &json!({ "salt": STANDARD.encode(salt), "agreement": agreement }))?;
    write(&out.join("status-list.json"), &status_list)?;
    write(&out.join("trqp-registry.json"), &registry)?;

    println!("issuer (requester):    {requester_did}");
    println!("subject (participant): {participant_did}");
    println!("asset binding sha256:  {asset_hash}");
    println!("wrote {}", out.display());
    Ok(())
}

fn write(path: &Path, value: &Value) -> Result<()> {
    Ok(std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?)
}
