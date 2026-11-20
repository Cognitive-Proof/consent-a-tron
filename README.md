# cawg-consent-test

A test implementation of a CAWG consent assertion (`cawg.consent`) that embeds a W3C Verifiable Credential. It is a proposed revision of the v0.22 pointer-only draft in [decentralized-identity/cawg-consent-assertion#5](https://github.com/decentralized-identity/cawg-consent-assertion/pull/5).

## Model

- **Consent is a VC (Data Model 2.0) embedded in `cawg.consent`.** The credential is immutable. Withdrawal is a Bitstring Status List entry, the only mutable part.
- **Layered schemas.** CAWG defines the minimum, in [schemas/cawg-consent-credential.schema.json](schemas/cawg-consent-credential.schema.json). An industry body extends it with `allOf` and decides which terms are public. The example is [schemas/example-actors-guild-consent-credential.schema.json](schemas/example-actors-guild-consent-credential.schema.json).
- **Public terms are readable; private terms are committed.** Pay and contract details stay off the file. The credential carries `privateTermsDigest` = SHA-256(salt ‖ JCS(agreement)), so either party can later prove the agreement.
- **Bound to the file** by the expected C2PA hard-binding hash. For JPEG this is computed before the manifest exists.
- **Signed by both parties**, as an `eddsa-jcs-2022` proof set:
  - the requester signs as issuer, and the participant cosigns;
  - the participant's key must also be the signer of a `cawg.identity` assertion that lists `cawg.consent` in its referenced assertions.
- **Issuer trust comes from TRQP.** The credential names a governance framework. The verifier asks its trust registry whether the issuer may issue this credential type.

## Run

Needs OpenSSL 3 (Homebrew `openssl@3`), Rust, and network access for the RFC 3161 timestamp.

```bash
./scripts/make-pki.sh
```

```bash
cargo run --bin mint -- fixtures/sample.jpg out
```

```bash
cargo run --bin sign -- fixtures/sample.jpg out/credential.json out/signed.jpg
```

```bash
cargo run --bin verify -- out/signed.jpg --agreement out/private-agreement.json
```

`verify --offline` skips the TRQP and status checks, as a disconnected reader would. `revoke` withdraws consent by updating only the status list.

```bash
./scripts/run-cases.sh
```

| Case | Expected |
|---|---|
| Signed asset, all checks | `cawg.consent.credential.valid` |
| Offline | valid, `status_unchecked` |
| Same credential on a different file | `binding_mismatch` |
| Participant proof removed | `participant_proof_missing` |
| Credential for someone other than the identity signer | `participant_mismatch` |
| Registry does not authorize issuer | `issuer_not_authorized` |
| Consent withdrawn | `revoked` (offline: valid, `status_unchecked`) |
| Public term edited after signing | `signature_invalid` |
| Wrong private agreement revealed | `private_terms_mismatch` |

## Findings for the spec and SDK

1. **The hard-binding hash is known in advance for JPEG.** The `c2pa.hash.data` value in the signed file equals the SHA-256 of the unsigned file, because the exclusion covers only the inserted manifest. BMFF/video (`c2pa.hash.bmff.v3`) is not tested yet.
2. **Offline readers see withdrawn consent as valid with status unchecked.** The spec has to say how a consumer treats `status_unchecked`. One option is to show the `validFrom` date and never present it as current.
3. **c2pa-rs (0.92.2) doesn't expose the CAWG identity signer's certificate publicly.** The verifier decodes the COSE_Sign1 `x5chain` from `Reader::detailed_json()`. A public accessor would be worth asking for upstream.
4. **Byte strings in `Reader::detailed_json()` are `b64'…'`,** while `c2patool --detailed` writes plain base64.

## Placeholders

- The `https://cawg.io/consent/v1` context and the schema `$id` URLs don't resolve. `eddsa-jcs-2022` signs JCS-canonical JSON, so no JSON-LD processing is needed.
- The TRQP registry is a local JSON file shaped like an authorization query (`entity_id`, `authority_id`, `action`, `resource`). It isn't TRQP's wire format.
- Everything in `pki/` and `out/` is test-only.
