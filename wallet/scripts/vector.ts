// Writes tests/vectors/js-proof.json: a credential with a proof made by the
// wallet's crypto module, for the Rust side to verify (tests/interop.rs).
// Run with: npm run vector   (Node 23+ runs .ts directly)

import { writeFileSync, mkdirSync } from "node:fs";
import { createProof, didKey, generateKeyPair, rawPublicKey, verifyProof } from "../src/crypto.ts";

const keys = await generateKeyPair();
const publicKey = await rawPublicKey(keys.publicKey);
const credential: Record<string, unknown> = {
  "@context": ["https://www.w3.org/ns/credentials/v2", "https://cawg.io/consent/v1"],
  type: ["VerifiableCredential", "CawgConsentCredential"],
  issuer: didKey(publicKey),
  validFrom: "2026-11-20T00:00:00Z",
  credentialSubject: { id: "mailto:alex@example.com", note: "unicode ✓ and \"quotes\"", n: 1.5 },
};
const proof = await createProof(credential, keys.privateKey, publicKey, "2026-11-20T00:00:00Z");
credential.proof = [proof];
if (!(await verifyProof(credential, proof))) throw new Error("JS proof does not verify in JS");

mkdirSync(new URL("../../tests/vectors/", import.meta.url), { recursive: true });
writeFileSync(new URL("../../tests/vectors/js-proof.json", import.meta.url), JSON.stringify(credential, null, 2) + "\n");
console.log("wrote tests/vectors/js-proof.json");
