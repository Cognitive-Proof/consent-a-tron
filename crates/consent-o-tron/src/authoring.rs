//! Authors the final file: a C2PA manifest signed by Consent-o-tron, with
//! the consent credential in `cawg.consent` and the cosigner's
//! `cawg.identity` assertion over it.
//!
//! The identity assertion is signed by the cosigner's wallet. c2pa-rs asks
//! the credential holder's [`RawSigner`] for a signature partway through
//! building the manifest; [`WalletSigner`] hands those bytes to the browser
//! and blocks until the wallet's signature comes back.

use std::{
    io::Cursor,
    path::Path,
    sync::mpsc,
    time::Duration,
};

use anyhow::Result;
use c2pa::{
    identity::{
        builder::{IdentityAssertionBuilder, IdentityAssertionSigner},
        x509::X509CredentialHolder,
    },
    settings::Settings,
    Builder, BuilderIntent, Context, DigitalSourceType, SigningAlg,
};
use c2pa_raw_crypto::{RawSigner, RawSignerError};
use cawg_consent_test::{c2pa_settings_toml, manifest_definition, pem_chain_to_der, pki, CONSENT_LABEL};
use serde_json::Value;

/// How long authoring waits for the cosigner's wallet.
const WALLET_TIMEOUT: Duration = Duration::from_secs(300);

/// What the browser needs to ask the wallet for the identity signature.
pub struct IdentityRequest {
    pub to_be_signed: Vec<u8>,
    /// Hash of the cawg.consent assertion, as referenced in the signer payload.
    pub consent_hash: Vec<u8>,
    pub reply: mpsc::Sender<Vec<u8>>,
}

/// A RawSigner whose private key lives in the cosigner's wallet.
pub struct WalletSigner {
    /// Called with each signing request; the browser collects it from there.
    pub post: Box<dyn Fn(IdentityRequest) + Send + Sync>,
}

impl RawSigner for WalletSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        let (reply, response) = mpsc::channel();
        (self.post)(IdentityRequest { to_be_signed: data.to_vec(), consent_hash: consent_hash(data).unwrap_or_default(), reply });
        let signature = response
            .recv_timeout(WALLET_TIMEOUT)
            .map_err(|_| RawSignerError::InternalError("the wallet did not sign in time".into()))?;
        if signature.len() != 64 {
            return Err(RawSignerError::InternalError("the wallet returned a malformed signature".into()));
        }
        Ok(signature)
    }

    fn alg(&self) -> SigningAlg {
        SigningAlg::Ed25519
    }

    fn max_signature_size(&self) -> usize {
        64
    }
}

/// Finds the cawg.consent hash in a COSE Sig_structure over a CAWG signer
/// payload: ["Signature1", protected, external_aad, payload].
fn consent_hash(sig_structure: &[u8]) -> Option<Vec<u8>> {
    use ciborium::Value as Cbor;
    let parts = ciborium::from_reader::<Cbor, _>(sig_structure).ok()?.into_array().ok()?;
    let payload: Cbor = ciborium::from_reader(parts.get(3)?.as_bytes()?.as_slice()).ok()?;
    let refs = payload
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_text() == Some("referenced_assertions"))?
        .1
        .as_array()?;
    refs.iter().find_map(|r| {
        let map = r.as_map()?;
        let field = |name: &str| map.iter().find(|(k, _)| k.as_text() == Some(name)).map(|(_, v)| v);
        field("url")?.as_text()?.ends_with(CONSENT_LABEL).then(|| field("hash")?.as_bytes().cloned())?
    })
}

/// Signs `asset` (JPEG). Blocks while the wallet signs, so call it from
/// `spawn_blocking`.
pub fn author(root: &Path, asset: &[u8], credential: &Value, cosigner_chain_pem: &str, wallet: WalletSigner) -> Result<Vec<u8>> {
    let settings = Settings::new().with_toml(&c2pa_settings_toml(root, false)?)?;
    let context = Context::new().with_settings(settings)?.into_shared();
    let definition = manifest_definition(std::slice::from_ref(credential), "consent-o-tron");
    let mut builder = Builder::from_shared_context(&context).with_definition(definition.to_string().as_str())?;
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));

    let claim_key = pki(root, "claim-signer.key")?;
    let claim_chain = pem_chain_to_der(&pki(root, "claim-signer.chain.pem")?)?;
    let claim_signer = c2pa_raw_crypto::signer_from_private_key(claim_key.as_bytes(), SigningAlg::Es256)?;
    let mut signer = IdentityAssertionSigner::new(claim_signer, claim_chain);

    let holder = X509CredentialHolder::from_raw_signer(Box::new(wallet), pem_chain_to_der(cosigner_chain_pem)?);
    let mut identity = IdentityAssertionBuilder::for_credential_holder(holder);
    identity.add_referenced_assertions(&[CONSENT_LABEL]);
    signer.add_identity_assertion(identity);

    let mut out = Cursor::new(Vec::new());
    builder.sign(&signer, "image/jpeg", &mut Cursor::new(asset), &mut out)?;
    Ok(out.into_inner())
}
