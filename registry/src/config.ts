import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** Repository root locally; APP_ROOT in the container. */
export const APP_ROOT = process.env.APP_ROOT ?? join(dirname(fileURLToPath(import.meta.url)), "../..");

// Same convention as the Rust sites: a .env at the repository root, never
// overriding variables already set.
try {
  for (const line of readFileSync(join(APP_ROOT, ".env"), "utf8").split("\n")) {
    const m = line.match(/^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (m && !line.trimStart().startsWith("#") && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
} catch {
  // no .env
}

/** A URL from the environment; empty counts as unset. */
function url(name: string, fallback: string): string {
  const value = process.env[name]?.trim();
  return (value || fallback).replace(/\/+$/, "");
}

export const REGISTRY_URL = url("REGISTRY_URL", "http://localhost:4005");
export const WALLET_URL = url("WALLET_URL", "http://localhost:4002");
export const CERT_SITE_URL = url("CERT_SITE_URL", "http://localhost:4001");
export const CONSENT_SITE_URL = url("CONSENT_SITE_URL", "http://localhost:4003");

/** did:web for the registry's host (the port, if any, percent-encoded). */
export const AUTHORITY_ID = `did:web:${new URL(REGISTRY_URL).host.replace(":", "%3A")}`;

/** The guild credential producers can be authorized to issue. */
export const CREDENTIAL_TYPE = "ExampleGuildLikenessConsentCredential";
export const ISSUE = { authority_id: AUTHORITY_ID, action: "issue", resource: CREDENTIAL_TYPE };
export const PUBLISH_STATUS = { authority_id: AUTHORITY_ID, action: "publish-status", resource: CREDENTIAL_TYPE };

/** Certificate emails that may use the admin pages. */
export const ADMIN_EMAILS = new Set(
  (process.env.REGISTRY_ADMIN_EMAILS ?? "")
    .split(",")
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean),
);

export const MONGODB_URI = process.env.MONGODB_URI?.trim() || "mongodb://localhost:27019";
export const MONGODB_DB = process.env.MONGODB_DB?.trim() || "consent_demo";

/** PKI material by file name, from PKI_* env vars (Cloud Run secrets) or <root>/pki. */
export function pki(name: string): string {
  const variable = `PKI_${name.toUpperCase().replace(/[-.]/g, "_")}`;
  const value = process.env[variable];
  if (value) return value;
  try {
    return readFileSync(join(APP_ROOT, "pki", name), "utf8");
  } catch {
    throw new Error(`${variable} is not set and pki/${name} is missing (run scripts/make-pki.sh)`);
  }
}

export const LISTEN_PORT = Number(process.env.PORT ?? 4005);
export const LISTEN_HOST = process.env.PORT ? "0.0.0.0" : "127.0.0.1";
