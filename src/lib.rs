//! Shared pieces of the CAWG consent credential test implementation.
//!
//! - `did:key` for Ed25519 keys
//! - the `eddsa-jcs-2022` Data Integrity cryptosuite, used as a proof set
//! - the salted private-terms digest
//! - Bitstring Status List encoding
//! - a mock TRQP authorization query
//! - schema validation of the credential

pub mod verify;

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ed25519_dalek::{pkcs8::DecodePrivateKey, Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub const CONSENT_LABEL: &str = "cawg.consent";
pub const BASE_SCHEMA_ID: &str = "https://cawg.io/consent/schemas/cawg-consent-credential.schema.json";
pub const GUILD_SCHEMA_ID: &str =
    "https://guild.example/consent/schemas/likeness-consent-credential.schema.json";

// ---------------------------------------------------------------- keys / did:key

/// Ed25519 multicodec prefix (0xed, varint-encoded).
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Reads a PKI file by name (e.g. `cawg-root.key`): from the environment
/// variable `PKI_CAWG_ROOT_KEY` when set (how Cloud Run passes secrets),
/// otherwise from `<root>/pki/<name>`.
pub fn pki(root: &Path, name: &str) -> Result<String> {
    let var = format!("PKI_{}", name.to_uppercase().replace(['-', '.'], "_"));
    match std::env::var(&var) {
        Ok(value) => Ok(value),
        Err(_) => std::fs::read_to_string(root.join("pki").join(name))
            .with_context(|| format!("{var} is not set and pki/{name} is missing (run scripts/make-pki.sh)")),
    }
}

pub fn load_ed25519_pem(pem: &str) -> Result<SigningKey> {
    SigningKey::from_pkcs8_pem(pem).map_err(|e| anyhow!("Ed25519 key: {e}"))
}

pub fn load_ed25519(path: &Path) -> Result<SigningKey> {
    let pem = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    SigningKey::from_pkcs8_pem(&pem).map_err(|e| anyhow!("{}: {e}", path.display()))
}

pub fn did_key(vk: &VerifyingKey) -> String {
    let mut bytes = ED25519_MULTICODEC.to_vec();
    bytes.extend_from_slice(vk.as_bytes());
    format!("did:key:z{}", bs58::encode(bytes).into_string())
}

/// Verification method URL for a did:key (`did:key:z…#z…`).
pub fn did_key_vm(vk: &VerifyingKey) -> String {
    let did = did_key(vk);
    let fragment = did.trim_start_matches("did:key:").to_string();
    format!("{did}#{fragment}")
}

/// Resolves a did:key DID or verification method to its Ed25519 key.
pub fn resolve_did_key(did_or_vm: &str) -> Result<VerifyingKey> {
    let mb = did_of_vm(did_or_vm)
        .strip_prefix("did:key:z")
        .ok_or_else(|| anyhow!("not a base58btc did:key: {did_or_vm}"))?;
    let bytes = bs58::decode(mb).into_vec()?;
    if bytes.len() != 34 || bytes[..2] != ED25519_MULTICODEC {
        bail!("did:key is not an Ed25519 key: {did_or_vm}");
    }
    Ok(VerifyingKey::from_bytes(bytes[2..].try_into()?)?)
}

pub fn did_of_vm(vm: &str) -> &str {
    vm.split('#').next().unwrap_or_default()
}

// ---------------------------------------------------------------- eddsa-jcs-2022

fn jcs(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_json_canonicalizer::to_vec(value)?)
}

/// The secured document minus its `proof` member. Proofs in a set are
/// independent: each one signs this, not the other proofs.
pub fn unsecured(doc: &Value) -> Result<Value> {
    let mut doc = doc.as_object().ok_or_else(|| anyhow!("credential is not an object"))?.clone();
    doc.remove("proof");
    Ok(Value::Object(doc))
}

/// hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(document)).
fn hash_data(proof_config: &Value, unsecured: &Value) -> Result<Vec<u8>> {
    let mut out = Sha256::digest(jcs(proof_config)?).to_vec();
    out.extend_from_slice(&Sha256::digest(jcs(unsecured)?));
    Ok(out)
}

fn proof_config(unsecured: &Value, proof: &Map<String, Value>) -> Value {
    let mut config = proof.clone();
    config.remove("proofValue");
    if let Some(ctx) = unsecured.get("@context") {
        config.insert("@context".into(), ctx.clone());
    }
    Value::Object(config)
}

/// Adds one `eddsa-jcs-2022` proof to the credential's proof set.
pub fn add_proof(doc: &mut Value, key: &SigningKey, created: &str) -> Result<()> {
    let unsecured = unsecured(doc)?;
    let mut proof = Map::new();
    proof.insert("type".into(), json!("DataIntegrityProof"));
    proof.insert("cryptosuite".into(), json!("eddsa-jcs-2022"));
    proof.insert("created".into(), json!(created));
    proof.insert("verificationMethod".into(), json!(did_key_vm(&key.verifying_key())));
    proof.insert("proofPurpose".into(), json!("assertionMethod"));

    let sig = key.sign(&hash_data(&proof_config(&unsecured, &proof), &unsecured)?);
    proof.insert("proofValue".into(), json!(format!("z{}", bs58::encode(sig.to_bytes()).into_string())));

    let obj = doc.as_object_mut().ok_or_else(|| anyhow!("credential is not an object"))?;
    let proofs = obj.entry("proof").or_insert_with(|| json!([]));
    proofs.as_array_mut().ok_or_else(|| anyhow!("proof is not an array"))?.push(Value::Object(proof));
    Ok(())
}

pub struct ProofResult {
    pub verification_method: String,
    pub valid: bool,
}

/// Verifies every proof in the credential's proof set.
pub fn verify_proofs(doc: &Value) -> Result<Vec<ProofResult>> {
    let unsecured = unsecured(doc)?;
    let proofs = match doc.get("proof") {
        Some(Value::Array(p)) => p.clone(),
        Some(p @ Value::Object(_)) => vec![p.clone()],
        _ => vec![],
    };
    proofs
        .iter()
        .map(|p| {
            let p = p.as_object().ok_or_else(|| anyhow!("proof is not an object"))?;
            let vm = p.get("verificationMethod").and_then(Value::as_str).unwrap_or_default().to_string();
            let valid = verify_one(&unsecured, p, &vm).unwrap_or(false);
            Ok(ProofResult { verification_method: vm, valid })
        })
        .collect()
}

fn verify_one(unsecured: &Value, proof: &Map<String, Value>, vm: &str) -> Result<bool> {
    if proof.get("cryptosuite").and_then(Value::as_str) != Some("eddsa-jcs-2022")
        || proof.get("proofPurpose").and_then(Value::as_str) != Some("assertionMethod")
    {
        return Ok(false);
    }
    let pv = proof.get("proofValue").and_then(Value::as_str).unwrap_or_default();
    let sig = bs58::decode(pv.strip_prefix('z').ok_or_else(|| anyhow!("proofValue not base58btc"))?).into_vec()?;
    let sig = Signature::from_slice(&sig)?;
    let key = resolve_did_key(vm)?;
    Ok(key.verify(&hash_data(&proof_config(unsecured, proof), unsecured)?, &sig).is_ok())
}

// ---------------------------------------------------------------- private terms

/// digest = SHA-256(salt || JCS(agreement)). The salt keeps small values
/// (such as a payment amount) from being guessed against the digest.
pub fn private_terms_digest(salt: &[u8], agreement: &Value) -> Result<String> {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(jcs(agreement)?);
    Ok(STANDARD.encode(h.finalize()))
}

// ---------------------------------------------------------------- status list

/// Minimum Bitstring Status List length (16 KiB) for herd privacy.
pub const STATUS_LIST_BITS: usize = 131_072;

pub fn encode_status_list(revoked: &[usize]) -> Result<String> {
    use std::io::Write;
    let mut bits = vec![0u8; STATUS_LIST_BITS / 8];
    for &i in revoked {
        bits[i / 8] |= 0x80 >> (i % 8);
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&bits)?;
    Ok(format!("u{}", URL_SAFE_NO_PAD.encode(gz.finish()?)))
}

pub fn status_bit(encoded_list: &str, index: usize) -> Result<bool> {
    use std::io::Read;
    let raw = URL_SAFE_NO_PAD.decode(
        encoded_list.strip_prefix('u').ok_or_else(|| anyhow!("encodedList not base64url multibase"))?,
    )?;
    let mut bits = Vec::new();
    flate2::read::GzDecoder::new(&raw[..]).read_to_end(&mut bits)?;
    let byte = bits.get(index / 8).ok_or_else(|| anyhow!("status index {index} out of range"))?;
    Ok(byte & (0x80 >> (index % 8)) != 0)
}

// ---------------------------------------------------------------- TRQP (mock)

/// Mock of a TRQP authorization query: is `entity_id` authorized by
/// `authority_id` to perform `action` on `resource`? The registry file
/// stands in for the trust registry the governance framework names.
pub fn trqp_authorized(registry: &Value, entity_id: &str, authority_id: &str, action: &str, resource: &str) -> bool {
    registry["authorizations"].as_array().is_some_and(|entries| {
        entries.iter().any(|e| {
            e["entity_id"] == entity_id
                && e["authority_id"] == authority_id
                && e["action"] == action
                && e["resource"] == resource
                && e["authorized"] == true
        })
    })
}

// ---------------------------------------------------------------- schema

/// Validates a credential against the guild schema, which pulls in the
/// CAWG base schema through `allOf`.
pub fn validate_schema(schema_dir: &Path, credential: &Value) -> Result<Vec<String>> {
    let read = |name: &str| -> Result<Value> {
        Ok(serde_json::from_str(&std::fs::read_to_string(schema_dir.join(name))?)?)
    };
    let base = read("cawg-consent-credential.schema.json")?;
    let guild = read("example-actors-guild-consent-credential.schema.json")?;
    let validator = jsonschema::options()
        .with_resource(BASE_SCHEMA_ID, jsonschema::Resource::from_contents(base)?)
        .build(&guild)
        .map_err(|e| anyhow!("schema: {e}"))?;
    Ok(validator.iter_errors(credential).map(|e| format!("{} at {}", e, e.instance_path)).collect())
}

// ---------------------------------------------------------------- credential

/// Governance framework and registry the command-line tools use; the demo
/// sites use the trust registry service's did:web authority instead.
pub const GOVERNANCE_FRAMEWORK: &str = "https://guild.example/gf/likeness-consent/v1";
pub const TRUST_REGISTRY: &str = "https://trqp.guild.example";

/// Everything that goes into a consent credential before it is signed.
pub struct CredentialParams<'a> {
    pub issuer_did: &'a str,
    /// `did:key:…`, or `mailto:…` when the participant is known only by the
    /// email their identity certificate attests.
    pub subject_id: &'a str,
    pub asset_hash_b64: &'a str,
    pub credential_type: &'a str,
    pub industry_schema_id: &'a str,
    pub status_list_url: &'a str,
    pub status_index: usize,
    /// TRQP `authority_id` of the governance framework issuers are authorized under.
    pub governance_framework: &'a str,
    /// Where that framework's trust registry answers TRQP queries.
    pub trust_registry: &'a str,
    /// Public terms, as defined by the industry schema.
    pub consent: Value,
    /// Private agreement; only its salted digest goes in the credential.
    pub agreement: &'a Value,
    pub salt: &'a [u8],
    pub valid_from: &'a str,
}

/// Builds the unsecured consent credential; proofs are added with [`add_proof`].
pub fn build_credential(p: &CredentialParams) -> Result<Value> {
    Ok(json!({
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://cawg.io/consent/v1"],
        "id": format!("urn:uuid:{}", uuid_v4()),
        "type": ["VerifiableCredential", "CawgConsentCredential", p.credential_type],
        "issuer": p.issuer_did,
        "validFrom": p.valid_from,
        "credentialSchema": [
            { "id": BASE_SCHEMA_ID, "type": "JsonSchema" },
            { "id": p.industry_schema_id, "type": "JsonSchema" }
        ],
        "credentialStatus": {
            "id": format!("{}#{}", p.status_list_url, p.status_index),
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": p.status_index.to_string(),
            "statusListCredential": p.status_list_url
        },
        "governanceFramework": { "id": p.governance_framework, "trustRegistry": p.trust_registry },
        "credentialSubject": {
            "id": p.subject_id,
            "consentDomain": "identity",
            "assetBinding": { "bindingType": "c2pa.hash.data", "alg": "sha256", "hash": p.asset_hash_b64 },
            "privateTermsDigest": { "alg": "sha256", "digest": private_terms_digest(p.salt, p.agreement)? },
            "consent": p.consent
        }
    }))
}

/// A Bitstring Status List credential, unsigned.
pub fn build_status_list(url: &str, issuer_did: &str, revoked: &[usize]) -> Result<Value> {
    Ok(json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": url,
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": issuer_did,
        "validFrom": now(),
        "credentialSubject": {
            "id": format!("{url}#list"),
            "type": "BitstringStatusList",
            "statusPurpose": "revocation",
            "encodedList": encode_status_list(revoked)?
        }
    }))
}

/// Builder definition for a manifest carrying the consent credential(s).
pub fn manifest_definition(credentials: &[Value], generator: &str) -> Value {
    json!({
        "claim_generator_info": [{ "name": generator, "version": env!("CARGO_PKG_VERSION") }],
        "assertions": [{
            "label": CONSENT_LABEL,
            "kind": "Json",
            "created": true,
            "data": { "credentials": credentials }
        }]
    })
}

pub fn uuid_v4() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

// ---------------------------------------------------------------- certificates

/// What the verifier needs from an identity signer's certificate.
pub struct SignerCert {
    pub ed25519_key: [u8; 32],
    /// rfc822Name subject alternative names.
    pub emails: Vec<String>,
}

pub fn signer_cert(der: &[u8]) -> Result<SignerCert> {
    use x509_parser::{extensions::GeneralName, prelude::*};
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| anyhow!("certificate: {e}"))?;
    let spki = cert.public_key();
    if spki.algorithm.algorithm.to_id_string() != "1.3.101.112" {
        bail!("signer certificate is not Ed25519");
    }
    let ed25519_key = spki.subject_public_key.data.as_ref().try_into()?;
    let emails = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::RFC822Name(e) => Some(e.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(SignerCert { ed25519_key, emails })
}

/// Splits a PEM certificate chain into DER certificates, leaf first.
pub fn pem_chain_to_der(chain_pem: &str) -> Result<Vec<Vec<u8>>> {
    let ders: Vec<Vec<u8>> = x509_parser::pem::Pem::iter_from_buffer(chain_pem.as_bytes())
        .map(|p| p.map(|p| p.contents).map_err(|e| anyhow!("PEM: {e}")))
        .collect::<Result<_>>()?;
    if ders.is_empty() {
        bail!("no certificates in PEM chain");
    }
    Ok(ders)
}

/// Checks that each certificate in the chain is signed by the next, and the
/// last by `root_pem`, then returns the leaf's key and emails. Validity
/// dates and EKUs are left to the c2pa trust check on the final file.
pub fn verify_cert_chain(chain_pem: &str, root_pem: &str) -> Result<SignerCert> {
    use x509_parser::prelude::*;
    let chain = pem_chain_to_der(chain_pem)?;
    let root = pem_chain_to_der(root_pem)?.remove(0);
    let mut certs: Vec<&[u8]> = chain.iter().map(Vec::as_slice).collect();
    if certs.last() != Some(&root.as_slice()) {
        certs.push(&root);
    }
    let parsed = certs
        .iter()
        .map(|der| X509Certificate::from_der(der).map(|(_, c)| c).map_err(|e| anyhow!("certificate: {e}")))
        .collect::<Result<Vec<_>>>()?;
    for pair in parsed.windows(2) {
        pair[0].verify_signature(Some(pair[1].public_key())).map_err(|_| anyhow!("certificate chain does not verify"))?;
    }
    signer_cert(&chain[0])
}

/// DER SubjectPublicKeyInfo for a raw Ed25519 public key.
pub fn ed25519_spki_der(key: &[u8; 32]) -> Vec<u8> {
    let mut der = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    der.extend_from_slice(key);
    der
}

// ---------------------------------------------------------------- c2pa settings

/// c2pa-rs settings: test trust anchors for both the claim signer (C2PA)
/// and the identity assertion signer (CAWG), plus signers when signing.
pub fn c2pa_settings_toml(root: &Path, with_signers: bool) -> Result<String> {
    let pem = |name: &str| pki(root, name);
    let mut toml = format!(
        r#"version = 1

[trust]
trust_config = """
1.3.6.1.5.5.7.3.4
1.3.6.1.5.5.7.3.36
"""

[[trust.anchors]]
trust_uri = "urn:consent-test:c2pa-root"
trust_kind = "manifest"
trust_anchors = """
{c2pa_root}"""

[[trust.anchors]]
trust_uri = "urn:consent-test:cawg-root"
trust_kind = "cawg"
trust_anchors = """
{cawg_root}"""

[verify]
verify_after_sign = true
"#,
        c2pa_root = pem("c2pa-root.pem")?,
        cawg_root = pem("cawg-root.pem")?,
    );
    if with_signers {
        toml += &format!(
            r#"
[signer.local]
alg = "es256"
sign_cert = """
{claim_chain}"""
private_key = """
{claim_key}"""
tsa_url = "http://timestamp.digicert.com"

[cawg_x509_signer.local]
alg = "ed25519"
sign_cert = """
{participant_chain}"""
private_key = """
{participant_key}"""
tsa_url = "http://timestamp.digicert.com"
referenced_assertions = ["{CONSENT_LABEL}"]
"#,
            claim_chain = pem("claim-signer.chain.pem")?,
            claim_key = pem("claim-signer.key")?,
            participant_chain = pem("participant.chain.pem")?,
            participant_key = pem("participant.key")?,
        );
    }
    Ok(toml)
}

pub fn sha256_b64(bytes: &[u8]) -> String {
    STANDARD.encode(Sha256::digest(bytes))
}

pub fn now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn did_key_round_trip() {
        let vk = key(1).verifying_key();
        let did = did_key(&vk);
        assert!(did.starts_with("did:key:z6Mk"));
        assert_eq!(resolve_did_key(&did_key_vm(&vk)).unwrap(), vk);
    }

    #[test]
    fn proof_set_is_order_independent_and_tamper_evident() {
        let mut doc = json!({"@context": ["https://www.w3.org/ns/credentials/v2"], "a": 1});
        add_proof(&mut doc, &key(1), "2026-11-20T00:00:00Z").unwrap();
        add_proof(&mut doc, &key(2), "2026-11-20T00:00:00Z").unwrap();
        assert!(verify_proofs(&doc).unwrap().iter().all(|p| p.valid));

        doc["proof"].as_array_mut().unwrap().reverse();
        assert!(verify_proofs(&doc).unwrap().iter().all(|p| p.valid));

        doc["a"] = json!(2);
        assert!(verify_proofs(&doc).unwrap().iter().all(|p| !p.valid));
    }

    #[test]
    fn status_list_bits() {
        let list = encode_status_list(&[0, 9, 131_071]).unwrap();
        assert!(status_bit(&list, 0).unwrap());
        assert!(!status_bit(&list, 1).unwrap());
        assert!(status_bit(&list, 9).unwrap());
        assert!(status_bit(&list, 131_071).unwrap());
    }

    #[test]
    fn private_terms_digest_depends_on_salt() {
        let agreement = json!({"fee": 500});
        assert_ne!(
            private_terms_digest(b"salt-a", &agreement).unwrap(),
            private_terms_digest(b"salt-b", &agreement).unwrap()
        );
    }
}
