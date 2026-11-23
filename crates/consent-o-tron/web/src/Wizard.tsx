import { useEffect, useMemo, useState } from "react";
import { getJson, humanize, postForm, renderAgreement, shortDate, shortLabel, showValue, type AgreementView, type Field, type Template } from "./api";
import { Modal } from "./Modal";
import { go, useSession } from "./session";
import { licenseFile, signAsProducer } from "./wallet";

const MAX_UPLOAD = 25 * 1024 * 1024;

type Values = Record<string, string | string[]>;

const defaults = (fields: Field[]): Values => Object.fromEntries(fields.map((f) => [f.name, f.default]));

export function Stepper({ steps, current }: { steps: string[]; current: number }) {
  return (
    <ol className="stepper">
      {steps.map((s, i) => (
        <li key={s} className={i < current ? "done" : i === current ? "current" : ""}>
          <span className="dot">{i < current ? "✓" : i + 1}</span>
          <span className="label">{s}</span>
        </li>
      ))}
    </ol>
  );
}

function FieldInput({ f, value, onChange }: { f: Field; value: string | string[]; onChange: (v: string | string[]) => void }) {
  if (f.type === "multiselect") {
    const selected = value as string[];
    return (
      <fieldset className="field">
        <legend>{f.label}</legend>
        <div className="toggles">
          {f.options.map((o) => {
            const on = selected.includes(o);
            return (
              <button
                key={o}
                type="button"
                className={`toggle${on ? " on" : ""}`}
                aria-pressed={on}
                onClick={() => onChange(on ? selected.filter((x) => x !== o) : [...selected, o])}
              >
                {humanize(o)}
              </button>
            );
          })}
        </div>
      </fieldset>
    );
  }
  // A long list reads better as a dropdown than as a row of buttons.
  if (f.type === "select" && f.options.length > 4) {
    return (
      <label className="field">
        <span>{f.label}</span>
        <select value={value as string} onChange={(e) => onChange(e.target.value)}>
          {f.options.map((o) => (
            <option key={o} value={o}>
              {humanize(o)}
            </option>
          ))}
        </select>
      </label>
    );
  }
  if (f.type === "select") {
    return (
      <fieldset className="field">
        <legend>{f.label}</legend>
        <div className="segmented" role="radiogroup">
          {f.options.map((o) => (
            <button key={o} type="button" role="radio" aria-checked={value === o} className={value === o ? "on" : ""} onClick={() => onChange(o)}>
              {humanize(o)}
            </button>
          ))}
        </div>
      </fieldset>
    );
  }
  return (
    <label className="field">
      <span>{f.label}</span>
      <input value={value as string} onChange={(e) => onChange(e.target.value)} />
    </label>
  );
}

export function Wizard({ template: t, onClose }: { template: Template; onClose: () => void }) {
  const { user } = useSession();
  const [step, setStep] = useState(0);
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [email, setEmail] = useState("");
  const [pub, setPub] = useState<Values>(() => defaults(t.public));
  const [priv, setPriv] = useState<Values>(() => defaults(t.private));
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<AgreementView | null>(null);
  const [sent, setSent] = useState(false);
  const [expiry, setExpiry] = useState("");
  // A template with no public terms or private terms skips that step.
  const steps = useMemo(
    () => ["File", ...(t.selfSigned ? [] : ["Person"]), ...(t.public.length || t.expiry ? ["Public terms"] : []), ...(t.private.length ? ["Private terms"] : []), "Review", "Sign"],
    [t],
  );
  const at = steps[step];
  const withdrawable = t.credentialType !== null;
  const tomorrow = new Date(Date.now() + 86_400_000).toISOString().slice(0, 10);

  const preview = useMemo(() => (file ? URL.createObjectURL(file) : null), [file]);
  useEffect(() => () => void (preview && URL.revokeObjectURL(preview)), [preview]);

  const pickFile = (f: File | undefined) => {
    setError("");
    if (!f) return;
    if (!/\.jpe?g$/i.test(f.name) && f.type !== "image/jpeg") return setError("Choose a JPEG image.");
    if (f.size > MAX_UPLOAD) return setError("The image must be 25 MB or smaller.");
    setFile(f);
  };

  const missing = (values: Values, fields: Field[]) =>
    fields.find((f) => (Array.isArray(values[f.name]) ? (values[f.name] as string[]).length === 0 : !(values[f.name] as string).trim()));

  const next = () => {
    setError("");
    if (at === "File" && !file) return setError("Add the image this consent is for.");
    if (at === "Person" && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim())) return setError("Enter the email of the person giving consent.");
    if (at === "Public terms" && missing(pub, t.public)) return setError(`Choose at least one option for “${missing(pub, t.public)!.label}”.`);
    if (at === "Public terms" && expiry && expiry < tomorrow) return setError("Choose an expiry date after today.");
    if (at === "Private terms" && missing(priv, t.private)) return setError(`Fill in “${missing(priv, t.private)!.label}”.`);
    setStep(step + 1);
  };

  const create = async () => {
    setBusy(true);
    setError("");
    try {
      const form = new FormData();
      form.append("template", t.id);
      form.append("asset", file!);
      if (!t.selfSigned) form.append("cosigner_email", email.trim());
      if (expiry) form.append("valid_until", expiry);
      for (const [prefix, values] of [["public.", pub], ["private.", priv]] as const) {
        for (const [k, v] of Object.entries(values)) for (const x of Array.isArray(v) ? v : [v]) form.append(prefix + k, x);
      }
      const { id } = await postForm<{ id: string }>("/api/agreements", form);
      setCreated(await getJson<AgreementView>(`/api/a/${id}`));
      setStep(steps.indexOf("Sign"));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const sign = async () => {
    setBusy(true);
    setError("");
    try {
      await (t.selfSigned ? licenseFile(created!) : signAsProducer(created!));
      setSent(true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  // After the credential exists, closing goes to the agreement rather than back to the gallery.
  const close = created ? () => go(`/a/${created.id}`) : onClose;
  const text = renderAgreement(t, { ...pub, ...priv }, email.trim(), user?.email ?? "");

  return (
    <Modal title={t.title} onClose={busy ? undefined : close} wide>
      <Stepper steps={steps} current={sent ? steps.length : step} />

      {at === "File" && (
        <div className="wstep">
          <h3>Which file is this consent for?</h3>
          <p className="muted">The credential is bound to this exact image. Any change to it breaks the binding.</p>
          <label
            className={`dropzone${dragging ? " over" : ""}${file ? " has-file" : ""}`}
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragging(false);
              pickFile(e.dataTransfer.files[0]);
            }}
          >
            <input type="file" accept="image/jpeg" onChange={(e) => pickFile(e.target.files?.[0])} />
            {file && preview ? (
              <>
                <img src={preview} alt="" />
                <span>
                  <strong>{file.name}</strong>
                  <span className="muted small">{(file.size / 1024 / 1024).toFixed(1)} MB · click to replace</span>
                </span>
              </>
            ) : (
              <span>
                <strong>Drop a JPEG here</strong> or click to choose one
                <span className="muted small">Up to 25 MB</span>
              </span>
            )}
          </label>
        </div>
      )}

      {at === "Person" && (
        <div className="wstep">
          <h3>Who is giving consent?</h3>
          <label className="field">
            <span>Their email</span>
            <input type="email" autoFocus value={email} onChange={(e) => setEmail(e.target.value)} placeholder="performer@example.com" />
          </label>
          <p className="note">
            The credential names them by this email. It must match the email on their NotSSL certificate, or they won't be able to
            consent.
          </p>
        </div>
      )}

      {at === "Public terms" && (
        <div className="wstep">
          <h3>Public terms</h3>
          <p className="badge-line">
            <span className="tag tag-open">Visible in the file</span> Anyone who has the file can read these.
          </p>
          {t.public.length === 0 && <p className="muted">This agreement has no public terms. The file says only that consent was given.</p>}
          {t.public.map((f) => (
            <FieldInput key={f.name} f={f} value={pub[f.name]} onChange={(v) => setPub({ ...pub, [f.name]: v })} />
          ))}
          {t.expiry && (
            <label className="field">
              <span>Consent expires (optional)</span>
              <input type="date" min={tomorrow} value={expiry} onChange={(e) => setExpiry(e.target.value)} />
            </label>
          )}
          {t.selfSigned && (
            <p className="note">
              Only you sign. Creative Commons licenses can't be revoked: once the file is out, anyone may use it on these terms.
            </p>
          )}
          {!withdrawable && !t.selfSigned && (
            <p className="note">
              This consent can't be withdrawn. Once you both sign, it lasts until the expiry date, or with no end date if you leave it
              empty.
            </p>
          )}
        </div>
      )}

      {at === "Private terms" && (
        <div className="wstep">
          <h3>Private terms</h3>
          <p className="badge-line">
            <span className="tag tag-locked">Hash only</span> Only a salted hash goes in the file. The text stays between you and the
            person consenting.
          </p>
          {t.private.map((f) => (
            <FieldInput key={f.name} f={f} value={priv[f.name]} onChange={(v) => setPriv({ ...priv, [f.name]: v })} />
          ))}
        </div>
      )}

      {at === "Review" && (
        <div className="wstep">
          <h3>Review the agreement</h3>
          <div className="review">
            <div className="review-side">
              {preview && <img className="review-img" src={preview} alt="" />}
              <dl className="terms">
                {!t.selfSigned && (
                  <div>
                    <dt>Person consenting</dt>
                    <dd>{email.trim()}</dd>
                  </div>
                )}
                {t.public.map((f) => (
                  <div key={f.name}>
                    <dt>{shortLabel(f.label)}</dt>
                    <dd>{showValue(pub[f.name])}</dd>
                  </div>
                ))}
                {t.expiry && (
                  <div>
                    <dt>Expires</dt>
                    <dd>{expiry ? shortDate(expiry) : "No end date"}</dd>
                  </div>
                )}
                <div>
                  <dt>Withdrawal</dt>
                  <dd>{withdrawable ? "Either of you can withdraw" : t.selfSigned ? "Can't be revoked" : "Can't be withdrawn"}</dd>
                </div>
              </dl>
            </div>
            <pre className="agreement-text">{text}</pre>
          </div>
        </div>
      )}

      {at === "Sign" && created && !sent && (
        <div className="wstep center">
          <img src="/mark.png" width={84} height={84} alt="" />
          {t.selfSigned ? (
            <>
              <h3>Sign the license</h3>
              <p className="muted">
                Your wallet signs the license, then attaches your identity to the file while Consent-O-Tron writes it.
              </p>
            </>
          ) : (
            <>
              <h3>Sign the consent request</h3>
              <p className="muted">
                Your wallet signs the credential as its issuer. Consent-O-Tron then emails <strong>{created.cosignerEmail}</strong> a link
                to review and consent.
              </p>
            </>
          )}
        </div>
      )}

      {sent && created && (
        <div className="wstep center">
          <div className="success-badge">✓</div>
          {t.selfSigned ? (
            <>
              <h3>Your file is licensed</h3>
              <p className="muted">The signed file carries your license. Download it from the agreement page.</p>
            </>
          ) : (
            <>
              <h3>Sent to {created.cosignerEmail}</h3>
              <p className="muted">The signed file is written as soon as they consent. You can follow along on the agreement page.</p>
            </>
          )}
        </div>
      )}

      {error && <p className="error">{error}</p>}

      <div className="wizard-actions">
        {step > 0 && at !== "Sign" && (
          <button className="btn btn-ghost" disabled={busy} onClick={() => setStep(step - 1)}>
            Back
          </button>
        )}
        <span className="spacer" />
        {step < steps.indexOf("Review") && (
          <button className="btn btn-primary" onClick={next}>
            Continue
          </button>
        )}
        {at === "Review" && (
          <button className="btn btn-primary" disabled={busy} onClick={create}>
            {busy ? "Creating…" : "Create credential"}
          </button>
        )}
        {at === "Sign" && !sent && (
          <button className="btn btn-primary" disabled={busy} onClick={sign}>
            {busy ? "Approve in your wallet…" : "Sign with wallet"}
          </button>
        )}
        {sent && created && (
          <button className="btn btn-primary" onClick={() => go(`/a/${created.id}`)}>
            View agreement
          </button>
        )}
      </div>
    </Modal>
  );
}
