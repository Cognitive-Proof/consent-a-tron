// Wallet cryptography: did:key, base58btc, and the eddsa-jcs-2022 Data
// Integrity cryptosuite. Uses only WebCrypto (globalThis.crypto), so the
// same module runs in the browser and in Node for the interop vector.
// Mirrors src/lib.rs on the Rust side.

import canonicalize from "canonicalize";

const subtle = globalThis.crypto.subtle;

/** Bytes backed by a plain ArrayBuffer, as WebCrypto requires. */
export type Bytes = Uint8Array<ArrayBuffer>;
const ED25519_MULTICODEC = [0xed, 0x01];
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58(bytes: Bytes): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return out;
}

export function fromBase58(s: string): Bytes {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error(`bad base58 character ${c}`);
    n = n * 58n + BigInt(i);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const c of s) {
    if (c !== "1") break;
    bytes.unshift(0);
  }
  return new Uint8Array(bytes);
}

export function b64(bytes: Bytes): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromB64(s: string): Bytes {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

const utf8 = (s: string) => new TextEncoder().encode(s);

export async function generateKeyPair(): Promise<CryptoKeyPair> {
  // Non-extractable: the private key can sign but can never be exported,
  // even by this app.
  return (await subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
}

export async function rawPublicKey(key: CryptoKey): Promise<Bytes> {
  return new Uint8Array(await subtle.exportKey("raw", key));
}

export function didKey(publicKey: Bytes): string {
  return `did:key:z${base58(new Uint8Array([...ED25519_MULTICODEC, ...publicKey]))}`;
}

export function didKeyVm(publicKey: Bytes): string {
  const did = didKey(publicKey);
  return `${did}#${did.slice("did:key:".length)}`;
}

export function publicKeyFromDid(didOrVm: string): Bytes {
  const did = didOrVm.split("#")[0];
  if (!did.startsWith("did:key:z")) throw new Error(`not a base58btc did:key: ${did}`);
  const bytes = fromBase58(did.slice("did:key:z".length));
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) throw new Error("did:key is not Ed25519");
  return bytes.slice(2);
}

export async function signBytes(privateKey: CryptoKey, data: Bytes): Promise<Bytes> {
  return new Uint8Array(await subtle.sign("Ed25519", privateKey, data));
}

/**
 * The bytes a trust registry's admin plugin (@cognitiveproof/cawg-trqp-plugin-admin)
 * verifies for an access request: the challenge bound to the exact permission.
 */
export function accessRequestMessage(challenge: string, did: string, permission: { authority_id: string; action: string; resource: string }): Bytes {
  return utf8(`trqp-access-request:${JSON.stringify([challenge, did, permission.authority_id, permission.action, permission.resource])}`);
}

/** What a party signs to withdraw consent; the server builds the same bytes. */
export function withdrawalMessage(challenge: string, credentialId: string, did: string): Bytes {
  return utf8(`consent-withdrawal:${JSON.stringify([challenge, credentialId, did])}`);
}

/** Signs a challenge string; servers verify with the same prefix. */
export async function signChallenge(privateKey: CryptoKey, purpose: string, challenge: string): Promise<string> {
  return b64(await signBytes(privateKey, utf8(`${purpose}:${challenge}`)));
}

type Json = Record<string, unknown>;

function jcs(value: unknown): Bytes {
  const s = canonicalize(value);
  if (s === undefined) throw new Error("value cannot be canonicalized");
  return utf8(s);
}

async function sha256(bytes: Bytes): Promise<Bytes> {
  return new Uint8Array(await subtle.digest("SHA-256", bytes));
}

/** The document minus `proof`: each proof in a set signs this. */
export function unsecured(doc: Json): Json {
  const { proof: _proof, ...rest } = doc;
  return rest;
}

/** hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(document)). */
async function hashData(proofConfig: Json, doc: Json): Promise<Bytes> {
  const [a, b] = await Promise.all([sha256(jcs(proofConfig)), sha256(jcs(doc))]);
  return new Uint8Array([...a, ...b]);
}

/** Creates one eddsa-jcs-2022 proof over the credential (not attached). */
export async function createProof(doc: Json, privateKey: CryptoKey, publicKey: Bytes, created: string): Promise<Json> {
  const base = unsecured(doc);
  const proof: Json = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    created,
    verificationMethod: didKeyVm(publicKey),
    proofPurpose: "assertionMethod",
  };
  const config = { ...proof, "@context": base["@context"] };
  const sig = await signBytes(privateKey, await hashData(config, base));
  return { ...proof, proofValue: `z${base58(sig)}` };
}

export async function verifyProof(doc: Json, proof: Json): Promise<boolean> {
  const base = unsecured(doc);
  const { proofValue, ...rest } = proof;
  if (rest.cryptosuite !== "eddsa-jcs-2022" || typeof proofValue !== "string") return false;
  const key = await subtle.importKey("raw", publicKeyFromDid(String(rest.verificationMethod)), { name: "Ed25519" }, false, ["verify"]);
  const config = { ...rest, "@context": base["@context"] };
  return subtle.verify("Ed25519", key, fromBase58(proofValue.slice(1)), await hashData(config, base));
}

/** True if `needle` occurs in `haystack`. Used to check what an identity signature covers. */
export function containsBytes(haystack: Bytes, needle: Bytes): boolean {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}
