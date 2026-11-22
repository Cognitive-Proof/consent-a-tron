// The JSON API served by consent-o-tron (crates/consent-o-tron/src/main.rs).

import type { RsManifestStore } from "./c2pa";

export type User = { email: string; did: string };

export type Field = {
  name: string;
  label: string;
  type: "multiselect" | "select" | "text";
  options: string[];
  default: string | string[];
};

export type Template = {
  id: string;
  title: string;
  description: string;
  category: string;
  updated: string;
  public: Field[];
  private: Field[];
  agreement: string;
  credentialType: string;
};

export type Stage = "awaiting_producer" | "awaiting_cosigner" | "authoring" | "signed" | "failed";

export type AgreementSummary = {
  id: string;
  title: string;
  templateId: string;
  assetName: string;
  role: "producer" | "cosigner";
  counterparty: string;
  stage: Stage;
  revoked: boolean;
  createdAt: string;
};

export type WalletAsset = { name: string; hash: string; thumbnail: string };

export type AgreementView = {
  id: string;
  title: string;
  templateId: string;
  createdAt: string;
  role: "producer" | "cosigner";
  invite: string | null;
  producerEmail: string;
  cosignerEmail: string;
  assetName: string;
  assetHash: string;
  walletAsset: WalletAsset;
  stage: Stage;
  revoked: boolean;
  /** Which party withdrew, if one did. */
  withdrawnBy: "producer" | "cosigner" | null;
  /** The key this viewer signed the credential with. */
  signerDid: string | null;
  error: string | null;
  /** The trust registry's reason the next step would be refused, if it would. */
  blocked: string | null;
  producerSigned: boolean;
  participantSigned: boolean;
  publicTerms: Record<string, string | string[]>;
  agreementText: string;
  credential: unknown;
  credentialWithProofs: unknown;
};

export type Outcome = { code: string; pass: boolean; explanation: string };

export type Report = {
  c2pa_state: string;
  /** The C2PA manifest store as c2pa-rs reads it; see c2pa.ts. */
  manifest_store: RsManifestStore;
  c2pa_failures: { code: string; url: string }[];
  credentials: {
    id: string;
    issuer: string;
    subject: string;
    valid_from: string;
    public_terms: Record<string, string | string[]>;
    outcomes: Outcome[];
    valid: boolean;
  }[];
  valid: boolean;
};

export type Email = { at: string; to: string; subject: string; body: string; link: string; delivery: string };

/** An API error, with the server's message and status. */
export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

async function parse<T>(res: Response): Promise<T> {
  const text = await res.text();
  if (!res.ok) throw new ApiError(text || res.statusText, res.status);
  return text ? JSON.parse(text) : ({} as T);
}

export const getJson = <T>(url: string) => fetch(url).then((r) => parse<T>(r));

export const postJson = <T = unknown>(url: string, body: unknown) =>
  fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }).then((r) => parse<T>(r));

export const postForm = <T>(url: string, body: FormData) => fetch(url, { method: "POST", body }).then((r) => parse<T>(r));

/** `notAllowed` → "Not allowed", `editorial` → "Editorial". Other text, such as "WORLD" or "Photo shoot", is left alone. */
export function humanize(value: string): string {
  if (!/^[a-z]+([A-Z][a-z]*)*$/.test(value)) return value;
  const spaced = value.replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

export function showValue(v: string | string[]): string {
  return Array.isArray(v) ? v.map(humanize).join(", ") : humanize(v);
}

/** The template's agreement text with the values filled in, as the server does. */
export function renderAgreement(
  t: Template,
  values: Record<string, string | string[]>,
  participant: string,
  producer: string,
): string {
  let text = t.agreement;
  for (const [k, v] of Object.entries(values)) text = text.replaceAll(`{{${k}}}`, Array.isArray(v) ? v.join(", ") : v);
  return text.replaceAll("{{participant}}", participant || "{{participant}}").replaceAll("{{producer}}", producer);
}

export function shortDate(iso: string): string {
  const d = new Date(iso.length === 10 ? `${iso}T12:00:00Z` : iso);
  return isNaN(+d) ? iso : d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

/** Template id → null if the producer may issue it, else the trust registry's reason. */
export type Permissions = { unavailable: boolean; refusals: Record<string, string | null> };

let templates: Promise<Template[]> | null = null;

/** The agreement templates, fetched once. */
export function getTemplates(): Promise<Template[]> {
  templates ??= getJson<Template[]>("/api/templates");
  return templates;
}

/** A field's label without its note, e.g. "Territory (ISO 3166-1 alpha-2, or WORLD)" → "Territory". */
export const shortLabel = (label: string) => label.replace(/\s*\(.*\)$/, "");
