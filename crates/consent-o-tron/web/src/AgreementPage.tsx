import { useCallback, useEffect, useState } from "react";
import { ApiError, getJson, getTemplates, postJson, shortDate, shortLabel, showValue, type AgreementView } from "./api";
import { Band, Frame } from "./Chrome";
import { Modal } from "./Modal";
import { StagePill } from "./Agreements";
import { useSession } from "./session";
import { consent, signAsProducer, type ConsentStep } from "./wallet";

function inviteParam() {
  return new URLSearchParams(location.search).get("invite");
}

/** Created → producer signed → consent given → file signed, then withdrawn if it was. */
function Timeline({ a }: { a: AgreementView }) {
  const steps: [string, boolean][] = [
    ["Created", true],
    ["Producer signed", a.producerSigned],
    ["Consent given", a.participantSigned],
    ["File signed", a.stage === "signed"],
  ];
  if (a.revoked) steps.push(["Withdrawn", true]);
  const current = a.stage === "failed" ? -1 : steps.findIndex(([, done]) => !done);
  return (
    <ol className="timeline">
      {steps.map(([label, done], i) => (
        <li key={label} className={label === "Withdrawn" ? "withdrawn" : done ? "done" : i === current ? "current" : ""}>
          <span className="dot">{label === "Withdrawn" ? "!" : done ? "✓" : i + 1}</span>
          <span className="label">{label}</span>
        </li>
      ))}
    </ol>
  );
}

/** Public terms, labeled as the templates label their fields. */
export function Terms({ terms }: { terms: Record<string, string | string[]> }) {
  const [labels, setLabels] = useState<Record<string, string>>({});
  useEffect(() => {
    getTemplates().then((ts) => setLabels(Object.fromEntries(ts.flatMap((t) => t.public.map((f) => [f.name, shortLabel(f.label)])))));
  }, []);
  return (
    <dl className="terms">
      {Object.entries(terms).map(([k, v]) => (
        <div key={k}>
          <dt>{labels[k] ?? k}</dt>
          <dd>{showValue(v)}</dd>
        </div>
      ))}
    </dl>
  );
}

const CONSENT_STEPS = ["Connect your identity", "Sign your consent", "Attach your identity to the file", "Write the signed file"];

function ConsentModal({ a, onDone, onClose }: { a: AgreementView; onDone: () => void; onClose: () => void }) {
  // How far along: the index of the step in progress, or CONSENT_STEPS.length when done.
  const [progress, setProgress] = useState(-1);
  const [error, setError] = useState("");
  const done = progress === CONSENT_STEPS.length;
  const running = progress >= 0 && !done && !error;

  const start = async () => {
    setError("");
    let identitySigned = false;
    const at: Record<ConsentStep, () => number> = {
      connect: () => 0,
      consent: () => 1,
      // Writing starts before the identity request arrives, and continues after it is signed.
      authoring: () => (identitySigned ? 3 : 2),
      identity: () => ((identitySigned = true), 2),
      done: () => CONSENT_STEPS.length,
    };
    try {
      await consent(a, (s) => setProgress(at[s]()));
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <Modal title="Give your consent" onClose={running ? undefined : done ? onDone : onClose}>
      <p className="muted">Your wallet opens over this page. It asks you to sign twice: once to consent, once to attach your identity.</p>
      <ol className="checklist">
        {CONSENT_STEPS.map((label, i) => (
          <li key={label} className={i < progress ? "done" : i === progress ? (error ? "failed" : "current") : ""}>
            <span className="dot" />
            {label}
          </li>
        ))}
      </ol>
      {error && <p className="error">{error}</p>}
      <div className="wizard-actions">
        <span className="spacer" />
        {done ? (
          <button className="btn btn-primary" onClick={onDone}>
            See the signed file
          </button>
        ) : (
          <button className="btn btn-primary" disabled={running} onClick={start}>
            {running ? "Follow your wallet…" : error ? "Try again" : "Consent with wallet"}
          </button>
        )}
      </div>
    </Modal>
  );
}

export function AgreementPage({ id }: { id: string }) {
  const { user, requireLogin } = useSession();
  const invite = inviteParam();
  const [a, setA] = useState<AgreementView | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState("");
  const [consenting, setConsenting] = useState(false);
  const [withdrawing, setWithdrawing] = useState(false);

  const load = useCallback(() => {
    getJson<AgreementView>(`/api/a/${id}${invite ? `?invite=${encodeURIComponent(invite)}` : ""}`).then(
      (v) => {
        setA(v);
        setError(null);
      },
      setError,
    );
  }, [id, invite]);

  useEffect(load, [load, user]);

  // While the file is being written, check back until it's done.
  useEffect(() => {
    if (a?.stage !== "authoring" || consenting) return;
    const timer = setTimeout(load, 2000);
    return () => clearTimeout(timer);
  }, [a, consenting, load]);

  if (error) {
    return (
      <Frame>
        <Band crumb={<a href="/">Home</a>} title="Agreement" />
        <section className="section">
          <div className="wrap empty">
            <img src="/mark.png" width={72} height={72} alt="" />
            <p>
              <strong>{error.status === 404 ? "This agreement doesn't exist." : error.message}</strong>
            </p>
            {error.status === 403 && !user && (
              <button className="btn btn-primary" onClick={() => requireLogin()}>
                Log in with wallet
              </button>
            )}
          </div>
        </section>
      </Frame>
    );
  }
  if (!a) return <Frame>{null}</Frame>;

  const q = a.role === "cosigner" && a.invite ? `?invite=${encodeURIComponent(a.invite)}` : "";
  const reviewing = a.role === "cosigner" && a.stage === "awaiting_cosigner";

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setActionError("");
    try {
      await fn();
      load();
    } catch (e) {
      setActionError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  let action = null;
  if (a.role === "producer" && a.stage === "awaiting_producer") {
    action = (
      <div className="panel">
        <p>
          Sign the consent request with your wallet. Consent-O-Tron then emails <strong>{a.cosignerEmail}</strong>.
        </p>
        <button className="btn btn-primary" disabled={busy} onClick={() => run(() => signAsProducer(a))}>
          {busy ? "Approve in your wallet…" : "Sign with wallet"}
        </button>
      </div>
    );
  } else if (a.role === "producer" && a.stage === "awaiting_cosigner") {
    action = (
      <div className="panel panel-wait">
        <p>
          Sent to <strong>{a.cosignerEmail}</strong>. The file is written once they consent. Emails are also listed in{" "}
          <a href="/outbox">Sent emails</a>.
        </p>
      </div>
    );
  } else if (reviewing) {
    action = (
      <div className="panel panel-consent">
        <h2>What happens when you consent</h2>
        <ol>
          <li>Your wallet asks you to confirm the terms and sign your consent.</li>
          <li>It then signs your CAWG identity into the file, covering that consent.</li>
          <li>Consent-O-Tron writes the signed file. Anyone with it can check your consent.</li>
          <li>You can withdraw your consent later. The file stays signed, but verifiers see it as withdrawn.</li>
        </ol>
        <button className="btn btn-primary btn-lg" onClick={() => setConsenting(true)}>
          Review and consent
        </button>
      </div>
    );
  } else if (a.stage === "awaiting_producer") {
    action = <div className="panel panel-wait">Waiting for {a.producerEmail} to sign the request.</div>;
  } else if (a.stage === "authoring") {
    action = <div className="panel panel-wait">Writing the signed file…</div>;
  } else if (a.stage === "failed") {
    action = <div className="panel panel-bad">Writing the file failed: {a.error ?? "unknown error"}</div>;
  } else if (a.stage === "signed") {
    action = (
      <div className={`panel ${a.revoked ? "panel-bad" : "panel-good"}`}>
        <p>
          {a.revoked
            ? "Consent has been withdrawn. The file stays signed, but verifiers that check status see the consent as withdrawn."
            : `The file is signed by Consent-O-Tron and carries the consent credential and ${a.cosignerEmail}'s identity assertion.`}
        </p>
        <div className="panel-actions">
          <a className="btn btn-primary" href={`/a/${a.id}/signed.jpg`} download>
            Download signed file
          </a>
          <a className="btn btn-ghost" href={`/a/${a.id}/verify${q}`}>
            Verify
          </a>
          {a.role === "cosigner" && !a.revoked && (
            <button className="btn btn-danger" onClick={() => setWithdrawing(true)}>
              Withdraw consent
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <Frame>
      <Band
        crumb={
          <>
            <a href="/">Home</a> / {user ? <a href="/agreements">My agreements</a> : <span>Agreement</span>} / <span>{a.title}</span>
          </>
        }
        title={reviewing ? `${a.producerEmail} asks for your consent` : a.title}
      >
        <div className="band-meta">
          <StagePill stage={a.stage} revoked={a.revoked} />
          <span className="muted">
            {reviewing ? a.title : `Between ${a.producerEmail} and ${a.cosignerEmail}`} · created {shortDate(a.createdAt)}
          </span>
        </div>
      </Band>

      <section className="section">
        <div className="wrap">
          <Timeline a={a} />
          {action}
          {actionError && <p className="error">{actionError}</p>}

          <div className="detail">
            <figure className="asset">
              <img src={`/a/${a.id}/asset`} alt="" />
              <figcaption>
                <strong>{a.assetName}</strong>
                <span className="mono muted small" title={a.assetHash}>
                  sha256 {a.assetHash.slice(0, 16)}…
                </span>
              </figcaption>
            </figure>
            <div className="detail-main">
              <div className="card">
                <div className="card-head">
                  <h2>Public terms</h2>
                  <span className="tag tag-open">Visible in the file</span>
                </div>
                <Terms terms={a.publicTerms} />
              </div>
              <div className="card">
                <div className="card-head">
                  <h2>Private agreement</h2>
                  <span className="tag tag-locked">Hash only</span>
                </div>
                <pre className="agreement-text">{a.agreementText}</pre>
              </div>
              <details className="card">
                <summary>Credential (JSON)</summary>
                <pre className="code">{JSON.stringify(a.credentialWithProofs, null, 2)}</pre>
              </details>
            </div>
          </div>
        </div>
      </section>

      {consenting && (
        <ConsentModal
          a={a}
          onClose={() => setConsenting(false)}
          onDone={() => {
            setConsenting(false);
            load();
          }}
        />
      )}
      {withdrawing && (
        <Modal title="Withdraw your consent?" onClose={() => setWithdrawing(false)}>
          <p>
            The file stays signed, but anyone who verifies it online will see that you withdrew consent. Withdrawal applies to uses after
            it is recorded. It can't be undone.
          </p>
          <div className="wizard-actions">
            <button className="btn btn-ghost" onClick={() => setWithdrawing(false)}>
              Keep my consent
            </button>
            <span className="spacer" />
            <button
              className="btn btn-danger"
              disabled={busy}
              onClick={() =>
                run(async () => {
                  await postJson(`/api/a/${a.id}/withdraw`, { invite: a.invite });
                  setWithdrawing(false);
                })
              }
            >
              Withdraw consent
            </button>
          </div>
        </Modal>
      )}
    </Frame>
  );
}
