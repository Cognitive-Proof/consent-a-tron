import { lazy, Suspense, useEffect, useState } from "react";
import { ApiError, getJson, postForm, shortDate, type Outcome, type Report } from "./api";
import { Band, Frame } from "./Chrome";
import { Terms } from "./AgreementPage";

const C2paView = lazy(() => import("./C2paView"));

const short = (code: string) => code.replace(/^cawg\.consent\.credential\./, "");

/** Plain words for the failures a reader is most likely to meet. */
const FAILURES: Record<string, string> = {
  signature_invalid: "The consent credential was changed after it was signed.",
  issuer_proof_missing: "The producer's signature is missing.",
  binding_mismatch: "This consent was given for a different file.",
  participant_proof_missing: "The person named in the consent never signed it.",
  participant_mismatch: "The person who signed isn't the person named in the consent.",
  identity_invalid: "The identity attached to the consent doesn't check out.",
  issuer_not_authorized: "The producer isn't authorized to issue this kind of consent.",
  private_terms_mismatch: "The private agreement doesn't match the one committed in the file.",
  expired: "This consent has expired.",
  schema_invalid: "The credential doesn't follow the consent schema.",
};

/** The headline, in plain words: valid, valid but unchecked status, withdrawn, or not valid. */
function verdict(report: Report): [string, string, string] {
  const outcomes = report.credentials.flatMap((c) => c.outcomes);
  const has = (code: string) => outcomes.some((o) => short(o.code) === code);
  if (!report.credentials.length) return ["red", "No consent credential", "This file has no CAWG consent credential."];
  if (has("revoked")) return ["red", "Consent withdrawn", "One of the parties has withdrawn it."];
  if (report.valid && has("status_unchecked"))
    return ["amber", "Valid when signed", "Withdrawal status wasn't checked, so this can't say whether consent still stands."];
  if (report.valid) return ["green", "Consent verified", "The file carries valid consent, signed by both parties, and it hasn't been withdrawn."];
  const failed = outcomes.find((o) => !o.pass);
  return ["red", "Not valid", failed ? (FAILURES[short(failed.code)] ?? failed.explanation) : `The C2PA manifest is ${report.c2pa_state}.`];
}

function Check({ o }: { o: Outcome }) {
  return (
    <li className={o.pass ? "pass" : "fail"}>
      <span className="mark-icon">{o.pass ? "✓" : "✗"}</span>
      <div>
        <strong>{short(o.code).replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase())}</strong>
        <span className="muted small">{o.explanation}</span>
        <code>{o.code}</code>
      </div>
    </li>
  );
}

export function ReportView({ report }: { report: Report }) {
  const [tone, title, text] = verdict(report);
  const c2paOk = ["Valid", "Trusted"].includes(report.c2pa_state);
  return (
    <div className="report">
      <div className={`verdict verdict-${tone}`}>
        <span className="verdict-icon">{tone === "green" ? "✓" : tone === "amber" ? "!" : "✗"}</span>
        <div>
          <h2>{title}</h2>
          <p>{text}</p>
        </div>
      </div>
      <div className="card">
        <div className="card-head">
          <h2>C2PA manifest</h2>
          <span className={`pill pill-${c2paOk ? "green" : "red"}`}>{report.c2pa_state}</span>
        </div>
        {report.c2pa_failures.length > 0 && (
          <ul className="checks">
            {report.c2pa_failures.map((f) => (
              <li key={f.code + f.url} className="fail">
                <span className="mark-icon">✗</span>
                <div>
                  <strong>{f.code}</strong>
                  <code>{f.url}</code>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
      {report.manifest_store.active_manifest && (
        <div className="card">
          <div className="card-head">
            <h2>Content Credentials</h2>
          </div>
          <p className="muted small">The file's C2PA manifest and CAWG identity. Use View more to step through the details.</p>
          <div className="c2pa-view">
            <Suspense fallback={<p className="muted">Loading…</p>}>
              <C2paView store={report.manifest_store} />
            </Suspense>
          </div>
        </div>
      )}
      {report.credentials.map((c) => (
        <div className="card" key={c.id}>
          <div className="card-head">
            <h2>Consent credential</h2>
            <span className={`pill pill-${c.valid ? "green" : "red"}`}>{c.valid ? "Valid" : "Not valid"}</span>
          </div>
          <p className="muted">
            Consent from <strong>{c.subject.replace(/^mailto:/, "")}</strong> · signed {shortDate(c.valid_from)}
          </p>
          <h3>Public terms</h3>
          <Terms terms={c.public_terms} />
          <h3>Checks</h3>
          <ul className="checks">
            {c.outcomes.map((o) => (
              <Check key={o.code} o={o} />
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}

function OnlineToggle({ offline, onChange }: { offline: boolean; onChange: (offline: boolean) => void }) {
  return (
    <div className="verify-mode">
      <div className="segmented" role="radiogroup" aria-label="Verification mode">
        <button role="radio" aria-checked={!offline} className={!offline ? "on" : ""} onClick={() => onChange(false)}>
          Online
        </button>
        <button role="radio" aria-checked={offline} className={offline ? "on" : ""} onClick={() => onChange(true)}>
          Offline
        </button>
      </div>
      <span className="muted small">Offline skips the trust registry and the status list, the way a disconnected reader would.</span>
    </div>
  );
}

export function VerifyUpload() {
  const [file, setFile] = useState<File | null>(null);
  const [offline, setOffline] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);

  useEffect(() => {
    if (!file) return;
    setBusy(true);
    setError("");
    setReport(null);
    const form = new FormData();
    form.append("file", file);
    if (offline) form.append("offline", "1");
    postForm<Report>("/api/verify", form)
      .then(setReport, (e: Error) => setError(e.message))
      .finally(() => setBusy(false));
  }, [file, offline]);

  return (
    <Frame>
      <Band crumb={<><a href="/">Home</a> / <span>Verify a file</span></>} title="Verify a file">
        <p className="muted">Check who consented to a file, to what, and whether that consent still stands. No account needed.</p>
      </Band>
      <section className="section">
        <div className="wrap narrow">
          <label
            className={`dropzone${dragging ? " over" : ""}`}
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragging(false);
              setFile(e.dataTransfer.files[0] ?? null);
            }}
          >
            <input type="file" accept="image/jpeg" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            <span>
              <strong>{file ? file.name : "Drop a signed JPEG here"}</strong>
              <span className="muted small">{file ? "Click or drop to check another file" : "or click to choose one"}</span>
            </span>
          </label>
          <OnlineToggle offline={offline} onChange={setOffline} />
          {busy && <p className="muted">Checking…</p>}
          {error && <p className="error">{error}</p>}
          {report && <ReportView report={report} />}
        </div>
      </section>
    </Frame>
  );
}

type AgreementReport = { assetName: string; title: string; party: boolean; revealed: boolean; report: Report };

export function VerifyAgreement({ id }: { id: string }) {
  const invite = new URLSearchParams(location.search).get("invite");
  const [offline, setOffline] = useState(false);
  const [reveal, setReveal] = useState(false);
  const [result, setResult] = useState<AgreementReport | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const q = new URLSearchParams();
    if (invite) q.set("invite", invite);
    if (offline) q.set("offline", "1");
    if (reveal) q.set("reveal", "1");
    setResult(null);
    getJson<AgreementReport>(`/api/a/${id}/verify?${q}`).then(setResult, (e: ApiError) => setError(e.message));
  }, [id, invite, offline, reveal]);

  const back = `/a/${id}${invite ? `?invite=${encodeURIComponent(invite)}` : ""}`;
  return (
    <Frame>
      <Band
        crumb={
          <>
            <a href="/">Home</a> / <a href={back}>{result?.title ?? "Agreement"}</a> / <span>Verify</span>
          </>
        }
        title="Verify"
      >
        <p className="muted">{result?.assetName}</p>
      </Band>
      <section className="section">
        <div className="wrap narrow">
          <OnlineToggle offline={offline} onChange={setOffline} />
          {result?.party && (
            <label className="reveal">
              <input type="checkbox" checked={reveal} onChange={(e) => setReveal(e.target.checked)} />
              Reveal the private agreement, and check that it matches the hash in the file
            </label>
          )}
          {error && <p className="error">{error}</p>}
          {!result && !error && <p className="muted">Checking…</p>}
          {result && <ReportView report={result.report} />}
          <p>
            <a href={back}>← Back to the agreement</a>
          </p>
        </div>
      </section>
    </Frame>
  );
}
