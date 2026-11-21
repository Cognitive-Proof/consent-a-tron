import { X509Certificate } from "node:crypto";
import { ed25519KeyFromDidKey } from "@cognitiveproof/cawg-trqp-plugin-admin";

export interface VerifiedCertificate {
  email: string;
  /** SHA-256 fingerprint of the leaf certificate. */
  fingerprint: string;
}

function splitPem(pem: string): X509Certificate[] {
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
  return blocks.map((b) => new X509Certificate(b));
}

/**
 * Checks that `chainPem` (leaf first) chains to `rootPem`, the leaf is in
 * date, and its Ed25519 key is the key behind `did`. Returns the leaf's
 * email address (rfc822Name SAN). Throws with a readable reason otherwise.
 */
export function verifyCertificate(chainPem: string, rootPem: string, did: string, now = new Date()): VerifiedCertificate {
  const chain = splitPem(chainPem);
  const [root] = splitPem(rootPem);
  if (chain.length === 0 || !root) throw new Error("no certificate");
  if (chain[chain.length - 1].fingerprint256 !== root.fingerprint256) chain.push(root);
  for (let i = 0; i + 1 < chain.length; i++) {
    if (!chain[i].verify(chain[i + 1].publicKey)) throw new Error("certificate chain does not verify to the CAWG root");
  }

  const leaf = chain[0];
  if (now < new Date(leaf.validFrom) || now > new Date(leaf.validTo)) throw new Error("certificate is not valid now");

  const jwk = leaf.publicKey.export({ format: "jwk" });
  if (jwk.crv !== "Ed25519" || !jwk.x) throw new Error("certificate key is not Ed25519");
  if (!Buffer.from(jwk.x, "base64url").equals(Buffer.from(ed25519KeyFromDidKey(did)))) {
    throw new Error("certificate is for a different key");
  }

  const email = (leaf.subjectAltName ?? "")
    .split(",")
    .map((s) => s.trim())
    .find((s) => s.startsWith("email:"))
    ?.slice("email:".length)
    .toLowerCase();
  if (!email) throw new Error("certificate has no email address");
  return { email, fingerprint: leaf.fingerprint256 };
}
