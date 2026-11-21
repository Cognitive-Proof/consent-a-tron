//! The wallet (TypeScript, WebCrypto) and this crate must agree on
//! eddsa-jcs-2022. The vector is regenerated with `npm run vector` in wallet/.

use cawg_consent_test::verify_proofs;

#[test]
fn rust_verifies_wallet_proof() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("vectors/js-proof.json")).expect("vector parses");
    let results = verify_proofs(&vector).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].valid, "JS-made proof did not verify in Rust");

    let mut tampered = vector.clone();
    tampered["credentialSubject"]["n"] = serde_json::json!(2);
    assert!(!verify_proofs(&tampered).unwrap()[0].valid);
}
