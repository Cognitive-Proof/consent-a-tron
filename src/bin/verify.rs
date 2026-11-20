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
use base64::{engine::general_purpose::STANDARD, Engine};
use c2pa::{settings::Settings, Context, Reader};
use cawg_consent_test::*;
use serde_json::Value;

const CODE: &str = "cawg.consent.credential";

struct Args {
    asset: PathBuf,
    offline: bool,
    status: PathBuf,
    registry: PathBuf,
    agreement: Option<PathBuf>,
}

fn parse_args() -> Result<Args> {
    let mut it = std::env::args().skip(1);
    let asset = PathBuf::from(it.next().ok_or_else(|| anyhow!("usage: verify <signed.jpg> [options]"))?);
    let dir = asset.parent().unwrap_or(Path::new(".")).to_path_buf();
    let mut args = Args {
        offline: false,
        status: dir.join("status-list.json"),
        registry: dir.join("trqp-registry.json"),
        agreement: None,
        asset,
    };
    while let Some(flag) = it.next() {
        let mut value = || it.next().map(PathBuf::from).ok_or_else(|| anyhow!("{flag} needs a value"));
        match flag.as_str() {
            "--offline" => args.offline = true,
            "--status" => args.status = value()?,
            "--registry" => args.registry = value()?,
            "--agreement" => args.agreement = Some(value()?),
            _ => bail!("unknown option {flag}"),
        }
    }
    Ok(args)
}

/// One verification outcome, printed as `code  explanation`.
struct Outcome {
    code: String,
    pass: bool,
    explanation: String,
}

fn outcome(code: &str, pass: bool, explanation: impl Into<String>) -> Outcome {
    Outcome { code: format!("{CODE}.{code}"), pass, explanation: explanation.into() }
}

/// A cawg.identity assertion that lists cawg.consent among its
/// referenced assertions, with the Ed25519 key of its X.509 signer.
struct Identity {
    label: String,
    valid: bool,
    signer_key: Option<[u8; 32]>,
}

fn main() -> Result<()> {
    let args = parse_args()?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    let settings = Settings::new().with_toml(&c2pa_settings_toml(root, false)?)?;
    let context = Context::new().with_settings(settings)?.into_shared();
    let reader = Reader::from_shared_context(&context).with_file(&args.asset)?;
    let summary: Value = serde_json::from_str(&reader.json())?;
    let detailed: Value = serde_json::from_str(&reader.detailed_json())?;

    let active = detailed["active_manifest"].as_str().ok_or_else(|| anyhow!("no active manifest"))?;
    let store = &detailed["manifests"][active]["assertion_store"];
    let failures = summary["validation_results"]["activeManifest"]["failure"].as_array().cloned().unwrap_or_default();

    println!("C2PA manifest: {}", summary["validation_state"].as_str().unwrap_or("unknown"));
    for f in &failures {
        println!("  failure  {}  {}", f["code"].as_str().unwrap_or_default(), f["url"].as_str().unwrap_or_default());
    }

    let identities = identities(store, &failures)?;
    let credentials = store[CONSENT_LABEL]["credentials"].as_array().cloned().unwrap_or_default();
    if credentials.is_empty() {
        bail!("no {CONSENT_LABEL} assertion with credentials");
    }

    let mut all_valid = true;
    for (i, credential) in credentials.iter().enumerate() {
        println!("\nCredential {i}: {}", credential["id"].as_str().unwrap_or("(no id)"));
        println!("  public terms: {}", credential["credentialSubject"]["consent"]);
        let outcomes = check_credential(&args, root, store, &identities, credential)?;
        let valid = outcomes.iter().all(|o| o.pass);
        for o in &outcomes {
            println!("  {} {:<48} {}", if o.pass { "ok  " } else { "FAIL" }, o.code, o.explanation);
        }
        let final_code = if valid { "valid" } else { "invalid" };
        println!("  => {CODE}.{final_code}");
        all_valid &= valid;
    }

    std::process::exit(if all_valid { 0 } else { 1 });
}

fn check_credential(
    args: &Args,
    root: &Path,
    store: &Value,
    identities: &[Identity],
    credential: &Value,
) -> Result<Vec<Outcome>> {
    let mut out = Vec::new();
    let issuer = credential["issuer"].as_str().unwrap_or_default();
    let subject = credential["credentialSubject"]["id"].as_str().unwrap_or_default();

    // Schema (CAWG base + industry extension).
    let errors = validate_schema(&root.join("schemas"), credential)?;
    out.push(if errors.is_empty() {
        outcome("schema_valid", true, "matches CAWG base and guild schemas")
    } else {
        outcome("schema_invalid", false, errors.join("; "))
    });

    // Proof set: every proof valid, with one from the issuer and one from the subject.
    let proofs = verify_proofs(credential)?;
    let bad: Vec<_> = proofs.iter().filter(|p| !p.valid).map(|p| p.verification_method.as_str()).collect();
    out.push(if bad.is_empty() && !proofs.is_empty() {
        outcome("signature_valid", true, format!("{} eddsa-jcs-2022 proofs verified", proofs.len()))
    } else {
        outcome("signature_invalid", false, format!("invalid proof(s): {}", bad.join(", ")))
    });
    let has_proof_by = |did: &str| proofs.iter().any(|p| p.valid && did_of_vm(&p.verification_method) == did);
    if !has_proof_by(issuer) {
        out.push(outcome("issuer_proof_missing", false, format!("no valid proof by issuer {issuer}")));
    }
    out.push(if has_proof_by(subject) {
        outcome("participant_proof_present", true, "participant cosigned")
    } else {
        outcome("participant_proof_missing", false, format!("no valid proof by participant {subject}"))
    });

    // Asset binding against the manifest's hard-binding assertion.
    let binding = &credential["credentialSubject"]["assetBinding"];
    let binding_type = binding["bindingType"].as_str().unwrap_or_default();
    let hard = &store[binding_type];
    out.push(
        if hard.is_object() && hard["alg"] == binding["alg"] && b64(&hard["hash"]) == b64(&binding["hash"]) {
            outcome("binding_match", true, format!("{binding_type} {} matches", binding["alg"].as_str().unwrap_or_default()))
        } else {
            outcome(
                "binding_mismatch",
                false,
                format!("credential {} vs manifest {}", b64(&binding["hash"]), b64(&hard["hash"])),
            )
        },
    );

    // Participant: the subject's key must be the key of a valid cawg.identity
    // signer that references this cawg.consent assertion.
    let subject_key = resolve_did_key(subject).ok().map(|k| k.to_bytes());
    let matched = identities.iter().find(|id| id.signer_key.is_some() && id.signer_key == subject_key);
    out.push(match matched {
        Some(id) if id.valid => outcome("participant_match", true, format!("subject key signed {}", id.label)),
        Some(id) => outcome("identity_invalid", false, format!("{} matches the subject but failed validation", id.label)),
        None => outcome(
            "participant_mismatch",
            false,
            "no cawg.identity referencing cawg.consent is signed by the subject's key",
        ),
    });

    // Validity period.
    if let Some(until) = credential["validUntil"].as_str() {
        if until < now().as_str() {
            out.push(outcome("expired", false, format!("validUntil {until}")));
        }
    }

    if args.offline {
        out.push(outcome("issuer_unchecked", true, "offline: TRQP registry not queried"));
        out.push(outcome(
            "status_unchecked",
            true,
            format!("offline: consent as signed at {}, withdrawal not checked", credential["validFrom"].as_str().unwrap_or("?")),
        ));
    } else {
        out.push(check_issuer(&args.registry, credential)?);
        out.push(check_status(&args.status, credential)?);
    }

    if let Some(path) = &args.agreement {
        out.push(check_agreement(path, credential)?);
    }
    Ok(out)
}

/// TRQP: is the issuer authorized under the credential's governance
/// framework to issue this credential type?
fn check_issuer(registry: &Path, credential: &Value) -> Result<Outcome> {
    let registry: Value = read_json(registry)?;
    let issuer = credential["issuer"].as_str().unwrap_or_default();
    let framework = credential["governanceFramework"]["id"].as_str().unwrap_or_default();
    let ty = industry_type(credential);
    Ok(if trqp_authorized(&registry, issuer, framework, "issue", ty) {
        outcome("issuer_authorized", true, format!("TRQP: authorized to issue {ty} under {framework}"))
    } else {
        outcome("issuer_not_authorized", false, format!("TRQP: {issuer} not authorized to issue {ty} under {framework}"))
    })
}

fn check_status(status: &Path, credential: &Value) -> Result<Outcome> {
    let entry = &credential["credentialStatus"];
    let list: Value = read_json(status)?;
    if list["id"] != entry["statusListCredential"] {
        return Ok(outcome("status_unchecked", false, "status list does not match statusListCredential"));
    }
    let list_issuer = list["issuer"].as_str().unwrap_or_default();
    let signed = verify_proofs(&list)?
        .iter()
        .any(|p| p.valid && did_of_vm(&p.verification_method) == list_issuer);
    if !signed || list_issuer != credential["issuer"] {
        return Ok(outcome("status_unchecked", false, "status list is not signed by the credential issuer"));
    }
    let index: usize = entry["statusListIndex"].as_str().unwrap_or_default().parse()?;
    let encoded = list["credentialSubject"]["encodedList"].as_str().unwrap_or_default();
    Ok(if status_bit(encoded, index)? {
        outcome("revoked", false, format!("withdrawn (status list bit {index} set)"))
    } else {
        outcome("status_active", true, format!("status list bit {index} clear"))
    })
}

/// Dispute path: a party reveals the agreement and salt.
fn check_agreement(path: &Path, credential: &Value) -> Result<Outcome> {
    let revealed: Value = read_json(path)?;
    let salt = STANDARD.decode(revealed["salt"].as_str().unwrap_or_default())?;
    let digest = private_terms_digest(&salt, &revealed["agreement"])?;
    Ok(if credential["credentialSubject"]["privateTermsDigest"]["digest"] == digest.as_str() {
        outcome("private_terms_match", true, "revealed agreement matches privateTermsDigest")
    } else {
        outcome("private_terms_mismatch", false, "revealed agreement does not match privateTermsDigest")
    })
}

fn industry_type(credential: &Value) -> &str {
    credential["type"]
        .as_array()
        .and_then(|t| t.iter().filter_map(Value::as_str).find(|t| !matches!(*t, "VerifiableCredential" | "CawgConsentCredential")))
        .unwrap_or("CawgConsentCredential")
}

fn identities(store: &Value, failures: &[Value]) -> Result<Vec<Identity>> {
    let consent_url = format!("self#jumbf=c2pa.assertions/{CONSENT_LABEL}");
    let mut out = Vec::new();
    for (label, ia) in store.as_object().into_iter().flatten() {
        if !(label == "cawg.identity" || label.starts_with("cawg.identity__")) {
            continue;
        }
        let refs: Value = match &ia["signer_payload"] {
            Value::String(s) => serde_json::from_str(s)?,
            v => v.clone(),
        };
        let references_consent = refs["referenced_assertions"]
            .as_array()
            .is_some_and(|r| r.iter().any(|a| a["url"] == consent_url.as_str()));
        if !references_consent {
            continue;
        }
        // Untrusted signers show up as failures against this assertion's URL.
        let suffix = format!("c2pa.assertions/{label}");
        let valid = !failures.iter().any(|f| f["url"].as_str().is_some_and(|u| u.ends_with(&suffix)));
        let signature = STANDARD.decode(b64(&ia["signature"]))?;
        out.push(Identity { label: label.clone(), valid, signer_key: ed25519_signer_key(&signature).ok() });
    }
    Ok(out)
}

/// Pulls the leaf certificate from the COSE_Sign1 x5chain header (label 33)
/// and returns its Ed25519 public key.
fn ed25519_signer_key(cose: &[u8]) -> Result<[u8; 32]> {
    use ciborium::Value as Cbor;
    let value: Cbor = ciborium::from_reader(cose)?;
    let parts = match value {
        Cbor::Tag(18, inner) => *inner,
        v => v,
    };
    let parts = parts.into_array().map_err(|_| anyhow!("COSE_Sign1 is not an array"))?;
    let protected: Cbor = ciborium::from_reader(parts[0].as_bytes().ok_or_else(|| anyhow!("no protected header"))?.as_slice())?;
    let headers = [protected, parts[1].clone()];
    let x5chain = headers
        .iter()
        .filter_map(|h| h.as_map())
        .flatten()
        .find(|(k, _)| k.as_integer() == Some(33.into()))
        .map(|(_, v)| v.clone())
        .context("no x5chain header")?;
    let leaf = match x5chain {
        Cbor::Bytes(b) => b,
        Cbor::Array(a) => a.first().and_then(|c| c.as_bytes().cloned()).context("empty x5chain")?,
        _ => bail!("bad x5chain"),
    };
    // Ed25519 SubjectPublicKeyInfo: SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING }.
    const SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    let at = leaf.windows(12).position(|w| w == SPKI_PREFIX).context("signer certificate is not Ed25519")?;
    Ok(leaf[at + 12..at + 44].try_into()?)
}

/// Byte strings in `Reader::detailed_json` use the json_b64 form `b64'<base64>'`.
fn b64(v: &Value) -> &str {
    let s = v.as_str().unwrap_or_default();
    s.strip_prefix("b64'").and_then(|s| s.strip_suffix('\'')).unwrap_or(s)
}

fn read_json(path: &Path) -> Result<Value> {
    serde_json::from_str(&std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?)
        .with_context(|| format!("parsing {}", path.display()))
}
