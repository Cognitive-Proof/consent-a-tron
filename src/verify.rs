//! Verification of the consent credential(s) in a signed asset, shared by
//! the `verify` CLI and Consent-o-tron's Verify page.

use std::io::Cursor;

use anyhow::{anyhow, bail, Context as _, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use c2pa::{settings::Settings, Context, Reader};
use serde::Serialize;
use serde_json::Value;

use crate::*;

const CODE: &str = "cawg.consent.credential";

/// What the verifier fetched. `None` means it could not, or chose not to
/// (offline), and the matching check reports `*_unchecked`.
#[derive(Default)]
pub struct Inputs {
    /// Asks the trust registry a TRQP authorization question.
    pub trqp: Option<TrqpQuery>,
    /// The governance framework (TRQP `authority_id`) this verifier trusts.
    /// A credential naming any other framework is not authorized: otherwise
    /// an issuer could point verifiers at a registry of its own.
    pub trusted_authority: Option<String>,
    /// The credential's status list credential.
    pub status_list: Option<Value>,
    /// A revealed private agreement (`{ salt, agreement }`), for disputes.
    pub agreement: Option<Value>,
}

/// One TRQP authorization question.
pub struct TrqpQuestion<'a> {
    pub entity_id: &'a str,
    pub authority_id: &'a str,
    pub action: &'a str,
    pub resource: &'a str,
    /// TRQP `context.time`: answer as of this moment instead of now.
    pub time: Option<&'a str>,
}

/// Answers a TRQP authorization question: `Ok(authorized)`, or an error if
/// the registry could not be asked.
pub type TrqpQuery = Box<dyn Fn(&TrqpQuestion) -> Result<bool> + Send + Sync>;

#[derive(Serialize)]
pub struct Report {
    pub c2pa_state: String,
    pub c2pa_failures: Vec<C2paFailure>,
    pub credentials: Vec<CredentialReport>,
    pub valid: bool,
}

#[derive(Serialize)]
pub struct C2paFailure {
    pub code: String,
    pub url: String,
}

#[derive(Serialize)]
pub struct CredentialReport {
    pub id: String,
    pub issuer: String,
    pub subject: String,
    pub valid_from: String,
    pub public_terms: Value,
    pub outcomes: Vec<Outcome>,
    pub valid: bool,
}

#[derive(Serialize)]
pub struct Outcome {
    pub code: String,
    pub pass: bool,
    pub explanation: String,
}

fn outcome(code: &str, pass: bool, explanation: impl Into<String>) -> Outcome {
    Outcome { code: format!("{CODE}.{code}"), pass, explanation: explanation.into() }
}

/// A `cawg.identity` assertion that lists `cawg.consent` among its
/// referenced assertions.
struct Identity {
    label: String,
    valid: bool,
    signer: Option<SignerCert>,
}

pub fn verify_asset(root: &std::path::Path, format: &str, asset: &[u8], inputs: &Inputs) -> Result<Report> {
    let settings = Settings::new().with_toml(&c2pa_settings_toml(root, false)?)?;
    let context = Context::new().with_settings(settings)?.into_shared();
    let reader = Reader::from_shared_context(&context).with_stream(format, Cursor::new(asset))?;
    let summary: Value = serde_json::from_str(&reader.json())?;
    let detailed: Value = serde_json::from_str(&reader.detailed_json())?;

    let active = detailed["active_manifest"].as_str().ok_or_else(|| anyhow!("no active manifest"))?;
    let store = &detailed["manifests"][active]["assertion_store"];
    let failures = summary["validation_results"]["activeManifest"]["failure"].as_array().cloned().unwrap_or_default();

    let identities = identities(store, &failures)?;
    let credentials = store[CONSENT_LABEL]["credentials"].as_array().cloned().unwrap_or_default();
    if credentials.is_empty() {
        bail!("no {CONSENT_LABEL} assertion with credentials");
    }

    let mut reports = Vec::new();
    for credential in &credentials {
        let outcomes = check_credential(root, store, &identities, credential, inputs)?;
        let str_of = |v: &Value| v.as_str().unwrap_or_default().to_string();
        reports.push(CredentialReport {
            id: str_of(&credential["id"]),
            issuer: str_of(&credential["issuer"]),
            subject: str_of(&credential["credentialSubject"]["id"]),
            valid_from: str_of(&credential["validFrom"]),
            public_terms: credential["credentialSubject"]["consent"].clone(),
            valid: outcomes.iter().all(|o| o.pass),
            outcomes,
        });
    }

    let c2pa_state = summary["validation_state"].as_str().unwrap_or("Unknown").to_string();
    Ok(Report {
        valid: matches!(c2pa_state.as_str(), "Valid" | "Trusted") && reports.iter().all(|r| r.valid),
        c2pa_failures: failures
            .iter()
            .map(|f| C2paFailure {
                code: f["code"].as_str().unwrap_or_default().into(),
                url: f["url"].as_str().unwrap_or_default().into(),
            })
            .collect(),
        c2pa_state,
        credentials: reports,
    })
}

fn check_credential(
    root: &std::path::Path,
    store: &Value,
    identities: &[Identity],
    credential: &Value,
    inputs: &Inputs,
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

    // Proof set: every proof valid, including one by the issuer.
    let proofs = verify_proofs(credential)?;
    let bad: Vec<_> = proofs.iter().filter(|p| !p.valid).map(|p| p.verification_method.as_str()).collect();
    out.push(if bad.is_empty() && !proofs.is_empty() {
        outcome("signature_valid", true, format!("{} eddsa-jcs-2022 proofs verified", proofs.len()))
    } else {
        outcome("signature_invalid", false, format!("invalid proof(s): {}", bad.join(", ")))
    });
    let proof_keys: Vec<[u8; 32]> = proofs
        .iter()
        .filter(|p| p.valid)
        .filter_map(|p| resolve_did_key(&p.verification_method).ok().map(|k| k.to_bytes()))
        .collect();
    if !proofs.iter().any(|p| p.valid && did_of_vm(&p.verification_method) == issuer) {
        out.push(outcome("issuer_proof_missing", false, format!("no valid proof by issuer {issuer}")));
    }

    // Asset binding against the manifest's hard-binding assertion.
    let binding = &credential["credentialSubject"]["assetBinding"];
    let binding_type = binding["bindingType"].as_str().unwrap_or_default();
    let hard = &store[binding_type];
    out.push(
        if hard.is_object() && hard["alg"] == binding["alg"] && b64(&hard["hash"]) == b64(&binding["hash"]) {
            outcome("binding_match", true, format!("{binding_type} {} matches", binding["alg"].as_str().unwrap_or_default()))
        } else {
            outcome("binding_mismatch", false, format!("credential {} vs manifest {}", b64(&binding["hash"]), b64(&hard["hash"])))
        },
    );

    // Participant. A did:key subject must be the identity signer's key; a
    // mailto: subject must be the verified email in the identity signer's
    // certificate. Either way the participant's proof must be made with
    // that same key.
    let subject_matches = |cert: &SignerCert| match subject.strip_prefix("mailto:") {
        Some(email) => cert.emails.iter().any(|e| e.eq_ignore_ascii_case(email)),
        None => resolve_did_key(subject).is_ok_and(|k| k.to_bytes() == cert.ed25519_key),
    };
    let matched = identities.iter().find(|id| id.signer.as_ref().is_some_and(subject_matches));
    match matched {
        Some(id) => {
            let key = id.signer.as_ref().map(|c| c.ed25519_key).unwrap_or_default();
            out.push(if proof_keys.contains(&key) {
                outcome("participant_proof_present", true, format!("participant cosigned with the key that signed {}", id.label))
            } else {
                outcome("participant_proof_missing", false, format!("no valid proof by the {} signer's key", id.label))
            });
            out.push(if id.valid {
                outcome("participant_match", true, format!("{subject} signed {}", id.label))
            } else {
                outcome("identity_invalid", false, format!("{} matches {subject} but failed validation", id.label))
            });
        }
        None => {
            if !proofs.iter().any(|p| p.valid && did_of_vm(&p.verification_method) == subject) && !subject.starts_with("mailto:") {
                out.push(outcome("participant_proof_missing", false, format!("no valid proof by participant {subject}")));
            }
            out.push(outcome(
                "participant_mismatch",
                false,
                format!("no cawg.identity referencing cawg.consent is signed by {subject}"),
            ));
        }
    }

    if let Some(until) = credential["validUntil"].as_str() {
        if until < now().as_str() {
            out.push(outcome("expired", false, format!("validUntil {until}")));
        }
    }

    out.push(match &inputs.trqp {
        Some(trqp) => check_issuer(trqp, inputs.trusted_authority.as_deref(), credential),
        None => outcome("issuer_unchecked", true, "offline: TRQP registry not queried"),
    });
    out.push(match (&inputs.status_list, &inputs.trqp) {
        (Some(list), Some(trqp)) => check_status(list, trqp, credential)?,
        _ => outcome(
            "status_unchecked",
            true,
            format!("offline: consent as signed at {}, withdrawal not checked", credential["validFrom"].as_str().unwrap_or("?")),
        ),
    });
    if let Some(revealed) = &inputs.agreement {
        out.push(check_agreement(revealed, credential)?);
    }
    Ok(out)
}

/// TRQP: was the issuer authorized under the trusted governance framework to
/// issue this credential type when the credential was signed (`validFrom`)?
/// Asking for that time means revoking a producer later doesn't invalidate
/// consent given while they were authorized.
fn check_issuer(trqp: &TrqpQuery, trusted: Option<&str>, credential: &Value) -> Outcome {
    let issuer = credential["issuer"].as_str().unwrap_or_default();
    let framework = credential["governanceFramework"]["id"].as_str().unwrap_or_default();
    let ty = industry_type(credential);
    if let Some(trusted) = trusted {
        if framework != trusted {
            return outcome("issuer_not_authorized", false, format!("credential names governance framework {framework}; this verifier trusts {trusted}"));
        }
    }
    let signed_at = credential["validFrom"].as_str();
    let question = TrqpQuestion { entity_id: issuer, authority_id: framework, action: "issue", resource: ty, time: signed_at };
    match trqp(&question) {
        Ok(true) => outcome("issuer_authorized", true, format!("TRQP: authorized to issue {ty} under {framework} at {}", signed_at.unwrap_or("now"))),
        Ok(false) => outcome("issuer_not_authorized", false, format!("TRQP: {issuer} was not authorized to issue {ty} under {framework} at {}", signed_at.unwrap_or("now"))),
        Err(e) => outcome("issuer_unchecked", false, format!("TRQP registry could not be asked: {e:#}")),
    }
}

/// The status list must be signed by a party the governance framework
/// authorizes to publish status for this credential type.
fn check_status(list: &Value, trqp: &TrqpQuery, credential: &Value) -> Result<Outcome> {
    let entry = &credential["credentialStatus"];
    if list["id"] != entry["statusListCredential"] {
        return Ok(outcome("status_unchecked", false, "status list does not match statusListCredential"));
    }
    let list_issuer = list["issuer"].as_str().unwrap_or_default();
    let signed = verify_proofs(list)?.iter().any(|p| p.valid && did_of_vm(&p.verification_method) == list_issuer);
    let framework = credential["governanceFramework"]["id"].as_str().unwrap_or_default();
    let ty = industry_type(credential);
    let question = TrqpQuestion { entity_id: list_issuer, authority_id: framework, action: "publish-status", resource: ty, time: None };
    if !signed || !trqp(&question).unwrap_or(false) {
        return Ok(outcome("status_unchecked", false, format!("status list signer {list_issuer} is not an authorized status publisher")));
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
fn check_agreement(revealed: &Value, credential: &Value) -> Result<Outcome> {
    let salt = STANDARD.decode(revealed["salt"].as_str().unwrap_or_default())?;
    let digest = private_terms_digest(&salt, &revealed["agreement"])?;
    Ok(if credential["credentialSubject"]["privateTermsDigest"]["digest"] == digest.as_str() {
        outcome("private_terms_match", true, "revealed agreement matches privateTermsDigest")
    } else {
        outcome("private_terms_mismatch", false, "revealed agreement does not match privateTermsDigest")
    })
}

pub fn industry_type(credential: &Value) -> &str {
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
        if !refs["referenced_assertions"].as_array().is_some_and(|r| r.iter().any(|a| a["url"] == consent_url.as_str())) {
            continue;
        }
        // Untrusted signers show up as failures against this assertion's URL.
        let suffix = format!("c2pa.assertions/{label}");
        let valid = !failures.iter().any(|f| f["url"].as_str().is_some_and(|u| u.ends_with(&suffix)));
        let signature = STANDARD.decode(b64(&ia["signature"]))?;
        let signer = cose_leaf_cert(&signature).and_then(|der| signer_cert(&der)).ok();
        out.push(Identity { label: label.clone(), valid, signer });
    }
    Ok(out)
}

/// Pulls the leaf certificate (DER) from a COSE_Sign1's x5chain header (label 33).
fn cose_leaf_cert(cose: &[u8]) -> Result<Vec<u8>> {
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
    match x5chain {
        Cbor::Bytes(b) => Ok(b),
        Cbor::Array(a) => a.first().and_then(|c| c.as_bytes().cloned()).context("empty x5chain"),
        _ => bail!("bad x5chain"),
    }
}

/// Byte strings in `Reader::detailed_json` use the json_b64 form `b64'<base64>'`.
fn b64(v: &Value) -> &str {
    let s = v.as_str().unwrap_or_default();
    s.strip_prefix("b64'").and_then(|s| s.strip_suffix('\'')).unwrap_or(s)
}
