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
- **Issuer trust comes from TRQP.** The credential names a governance framework. The verifier asks that framework's trust registry whether the issuer was authorized to issue this credential type when the credential was signed. The verifier trusts only a configured framework, never the registry a credential points to.

## Demo sites

Four sites show the flow with real people.

| Site | Port | What it does |
|---|---|---|
| Certificate site, "NotSSL" ([crates/cert-site](crates/cert-site/src/main.rs)) | 4001 | A React home page ([web](crates/cert-site/web/src/Home.tsx)); links with no content go to `/demo`. Enrollment at `/enroll`, modeled on NIST LOA2 / IAL2: email and a single-use 24-hour mailbox link; a Stripe test payment, where the card issuer checks the billing address; name, date of birth and ID number validated against a mock records bureau (`/records`), with ID and face photos discarded; a 6-digit enrollment code sent to the email of record; and finally an Ed25519 certificate from the CAWG test CA with the verified email. A certificate alone doesn't authorize issuing: that comes from the trust registry. |
| Wallet ([wallet](wallet/src/main.ts)) | 4002 | Static app. It creates non-exportable Ed25519 keys (WebCrypto, IndexedDB), holds certificates, and signs on request. |
| Consent-o-tron ([crates/consent-o-tron](crates/consent-o-tron/src/main.rs)) | 4003 | The producer picks a template, uploads a JPEG, names the person consenting by email, and signs. The person consenting reviews, consents, and signs their CAWG identity assertion while the file is authored. It also handles withdrawal and verification of any file. |
| Trust Registry ([registry](registry/src/server.ts)) | 4005 | The guild's TRQP 2.0 registry (`POST /authorization`), built on [`@cognitiveproof/cawg-trqp`](https://github.com/Cognitive-Proof/cawg-trqp-verifer) and its admin plugin. Producers sign in with their wallet (CAWG certificate required) and request permission to `issue`; administrators (`REGISTRY_ADMIN_EMAILS`) approve, reject and revoke. Its authority is `did:web` for its host, with a DID document naming the TRQP endpoint and governance framework. |

**How the pieces connect:**
- **Wallet dialog.** Sites open the wallet in a dialog (an iframe) and talk to it with `postMessage` ([wallet-client.js](crates/demo-common/src/wallet-client.js)). The wallet answers only allow-listed origins.
- **Same site required.** An embedded wallet can reach its keys only when the wallet and the sites are the same site. `localhost:*` is; in production, use subdomains of one domain, not separate `*.run.app` URLs.
- **Credential subject.** It is `mailto:<email>`: the producer signs before the person consenting has connected a wallet. The verifier requires the identity signer's certificate to carry that email, and the participant proof to use that certificate's key.
- **Trust registry.** Credentials name the registry's `did:web` authority. Consent-o-tron's verifier asks it two TRQP questions: was the issuer authorized to `issue` at the credential's `validFrom` (`context.time`), and may the status list's signer `publish-status`. Answers are time-aware, so revoking a producer stops new credentials but consent given while they were authorized stays valid.
- **Issuing checks.** Consent-o-tron asks the registry the same `issue` question before it issues, so a producer can't make a credential the verifier would reject:
  1. When creating an agreement, at the `validFrom` the credential will carry. Producers without permission see a link to request access instead of the agreement form.
  2. When the producer signs, both at `validFrom` and now, so access revoked after creating the agreement stops it being sent for consent.
  3. Before recording the cosigner's consent and writing the file, now. A producer revoked after signing can't finish the file, even though the verifier, asking about `validFrom`, would still accept it.

  A registry outage blocks these steps rather than skipping the check.
- **Identity signature.** Consent-o-tron builds the manifest with c2pa-rs. The identity signature comes from a `RawSigner` that waits for the person's wallet ([authoring.rs](crates/consent-o-tron/src/authoring.rs)). The wallet signs only if the bytes reference `cawg.consent`. For the exact assertion hash it relies on Consent-o-tron.

**Storage:**
- MongoDB holds enrollments, agreements, sessions, the registry's requests, grants and audit log, and sent emails.
- Files go to a Google Cloud Storage bucket (`GCS_BUCKET`), or to `data/blobs/` locally.
- Email goes through Resend (`RESEND_API_KEY`). Every email is also listed on each site's `/outbox`.

Run locally:

```bash
./scripts/make-pki.sh
```

```bash
docker compose up -d mongo
```

```bash
cp .env.example .env
```

Build the NotSSL home page with `npm install && npm run build` in `crates/cert-site/web/` (or `npm run dev` there for live editing on port 4004). Then start `cargo run -p cert-site`, `cargo run -p consent-o-tron`, and `npm run dev` in `wallet/` and in `registry/` (after `npm install` in each). Set `REGISTRY_ADMIN_EMAILS` to the certificate email of whoever approves requests. Without Stripe or Resend keys, payment is simulated and emails appear only on `/outbox`.

`npm run vector` in `wallet/` regenerates [tests/vectors/js-proof.json](tests/vectors/js-proof.json). [tests/interop.rs](tests/interop.rs) checks that a proof made by the wallet's TypeScript verifies in Rust.

## Deployment (Google Cloud)

Pushes to `main` deploy to the `consent-o-tron` project ([.github/workflows/deploy.yml](.github/workflows/deploy.yml)). GitHub authenticates through Workload Identity Federation, so no keys are stored in GitHub.

| Service | URL | Notes |
|---|---|---|
| `cert-site` | https://certs.cognitive-proof.com | |
| `wallet` | https://wallet.cognitive-proof.com | nginx; only the sites may frame it |
| `consent-o-tron` | https://consent.cognitive-proof.com | one instance, CPU always on, for the in-memory wallet hand-off |
| `trust-registry` | https://registry.cognitive-proof.com | admins: `REGISTRY_ADMIN_EMAILS` in the workflow |

- **Data:** Firestore (Enterprise, MongoDB compatible), database `consent-demo`. The connection string is in the `MONGODB_URI` secret. Queries avoid filter-plus-sort combinations, so no composite indexes are needed.
- **Files:** bucket `gs://consent-o-tron-files`.
- **PKI:** a separate deployment set of test CAs, in `PKI_*` secrets.
- **Optional secrets:** add `STRIPE_SECRET_KEY` (sk_test_ only), `RESEND_API_KEY` and `EMAIL_FROM`. The next deploy picks them up.

## Run the command-line test

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
- The command-line `verify` reads a local JSON file in place of a TRQP registry, without time-aware answers; the demo sites use the real registry.
- Everything in `pki/` and `out/` is test-only.
