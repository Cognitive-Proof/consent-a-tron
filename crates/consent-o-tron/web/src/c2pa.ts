// Converts the manifest store c2pa-rs's `Reader::json` returns (snake_case,
// assertions as a list) into the `VerificationOutcome` that
// c2pa-react-component and its CAWG plugin display.
import type { Manifest, ManifestEntry, ManifestStore, VerificationOutcome } from "c2pa-react-component-types";

type RsAssertion = { label: string; data: unknown; instance?: number };
type RsManifest = {
  label?: string;
  title?: string;
  instance_id?: string;
  claim_generator?: string;
  claim_generator_info?: ManifestEntry["claimGeneratorInfo"];
  claim_version?: number;
  signature_info?: ManifestEntry["signatureInfo"];
  assertions?: RsAssertion[];
  ingredients?: ManifestEntry["ingredients"];
};
export type RsManifestStore = {
  active_manifest?: string;
  manifests?: Record<string, RsManifest>;
  validation_status?: ManifestStore["validation_status"];
  validation_results?: ManifestStore["validation_results"];
  validation_state?: ManifestStore["validation_state"];
};

function entry(label: string, m: RsManifest): ManifestEntry {
  return {
    label,
    id: label,
    title: m.title,
    instanceId: m.instance_id,
    claimGenerator: m.claim_generator ?? null,
    claimGeneratorInfo: m.claim_generator_info,
    claim_version: m.claim_version,
    signatureInfo: m.signature_info,
    // A repeated label gets c2pa's `__N` instance suffix, so each one is kept.
    assertions: Object.fromEntries(
      (m.assertions ?? []).map((a) => [a.instance && a.instance > 1 ? `${a.label}__${a.instance}` : a.label, a.data]),
    ),
    // Thumbnails are resources inside the file, which the verify API doesn't serve.
    thumbnail: null,
    ingredients: m.ingredients ?? [],
  };
}

export function toOutcome(store: RsManifestStore): VerificationOutcome {
  const entries = Object.fromEntries(Object.entries(store.manifests ?? {}).map(([label, m]) => [label, entry(label, m)]));
  const manifests: Manifest[] = Object.values(entries).map((e) => ({
    id: e.id ?? "",
    title: e.title ?? "",
    claimGenerator: e.claimGenerator ?? null,
    claimGeneratorInfo: (e.claimGeneratorInfo ?? []).map((g) => ({ name: g.name, "org.contentauth.c2pa_rs": g["org.contentauth.c2pa_rs"] ?? "" })),
    instanceId: e.instanceId ?? "",
    signatureInfo: {
      alg: e.signatureInfo?.alg ?? "",
      issuer: e.signatureInfo?.issuer ?? "",
      common_name: e.signatureInfo?.common_name ?? "",
      cert_serial_number: e.signatureInfo?.cert_serial_number ?? "",
    },
    assertions: e.assertions ?? {},
    credentials: [],
    thumbnail: null,
    ingredients: [],
  }));
  return {
    state: store.validation_state !== "Invalid",
    manifests,
    manifestStore: store.active_manifest
      ? {
          activeManifest: store.active_manifest,
          manifests: entries,
          validation_status: store.validation_status,
          validation_results: store.validation_results,
          validation_state: store.validation_state,
        }
      : undefined,
  };
}
