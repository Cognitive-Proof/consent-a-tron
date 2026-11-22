// Consent Wallet: holds Ed25519 identities and their CAWG certificates,
// and signs for other sites on request.
//
// Protocol: a site embeds this page in an iframe (or opens it in a popup)
// with `?request`, waits for { type: "ready" }, then posts requests. Each request carries an `id`; the
// reply carries the same `id`. Only ALLOWED_ORIGINS are answered.
//
//   connect              { challenge }                   -> { did, email, certChainPem, signature }
//   certificate:request  { challenge, email }            -> { did, publicKey, signature }
//   certificate:deliver  { certChainPem, email, issuer } -> { did }
//   credential:sign      { credential, role, asset, counterparty?, agreementText? } -> { proof }
//   identity:sign        { toBeSigned, consentHash, asset }          -> { signature }
//   registry:request     { challenge, permission, entityId }         -> { did, signature }
//
// A declined or failed request gets { type: "error", message }.

import "./style.css";
import {
  accessRequestMessage,
  b64,
  containsBytes,
  createProof,
  didKey,
  fromB64,
  generateKeyPair,
  rawPublicKey,
  signBytes,
  signChallenge,
} from "./crypto";
import { history, identities, type Identity } from "./store";

// The sites this wallet answers, set at build time (see .env.example).
const SITES: Record<string, string> = {
  [import.meta.env.VITE_CERT_SITE_URL ?? "http://localhost:4001"]: "Certificate site",
  [import.meta.env.VITE_CONSENT_SITE_URL ?? "http://localhost:4003"]: "Consent-O-Tron",
  [import.meta.env.VITE_REGISTRY_URL ?? "http://localhost:4005"]: "Trust Registry",
};
const ALLOWED_ORIGINS = new Set(Object.keys(SITES).map((url) => new URL(url).origin));

const app = document.querySelector<HTMLDivElement>("#app")!;
/** The site asking: our embedding page, or the window that opened us. */
const peer: Window | null = window.parent !== window ? window.parent : window.opener;
const inRequestMode = new URLSearchParams(location.search).has("request") && !!peer;

/** Identity chosen in this popup; later requests in the session reuse it. */
let sessionIdentity: Identity | undefined;

type Request = { id: string; type: string; [k: string]: unknown };

// ------------------------------------------------------------------ helpers

function h(s: unknown): string {
  return String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function short(did: string): string {
  return did.length > 28 ? `${did.slice(0, 18)}…${did.slice(-6)}` : did;
}

function siteName(origin: string): string {
  return Object.entries(SITES).find(([url]) => new URL(url).origin === origin)?.[1] ?? origin;
}

function now(): string {
  return new Date().toISOString().replace(/\.\d+Z$/, "Z");
}

async function newIdentity(label: string): Promise<Identity> {
  const keys = await generateKeyPair();
  const publicKey = await rawPublicKey(keys.publicKey);
  const identity: Identity = {
    id: crypto.randomUUID(),
    label: label.trim() || "Unnamed identity",
    did: didKey(publicKey),
    publicKey: b64(publicKey),
    keys,
    createdAt: now(),
  };
  await identities.put(identity);
  return identity;
}

// ------------------------------------------------------------------ home

async function renderHome() {
  const [all, past] = await Promise.all([identities.all(), history.all()]);
  app.innerHTML = `
    <header><h1>Consent Wallet</h1><p class="muted">Keys are created here and can't be exported.</p></header>
    <section>
      <h2>Identities</h2>
      ${all.length ? "" : `<p class="muted">No identities yet.</p>`}
      ${all
        .map(
          (i) => `
        <article class="card">
          <div class="row"><strong>${h(i.label)}</strong>
            <span class="badge ${i.certChainPem ? "ok" : ""}">${i.certChainPem ? "Certified" : "No certificate"}</span></div>
          <div class="mono muted" title="${h(i.did)}">${h(short(i.did))}</div>
          ${i.email ? `<div>${h(i.email)} · issued by ${h(i.certIssuer ?? "")}</div>` : ""}
          <div class="row actions">
            ${i.certChainPem ? `<button data-export="${h(i.id)}" class="secondary">Download certificate</button>` : ""}
            <button data-remove="${h(i.id)}" class="link danger">Delete</button>
          </div>
        </article>`,
        )
        .join("")}
      <form id="new" class="row">
        <input name="label" placeholder="Name, e.g. Alex (performer)" required />
        <button>New identity</button>
      </form>
      <p class="muted">To certify an identity, start on the Certificate site; it will open this wallet.</p>
    </section>
    <section>
      <h2>Activity</h2>
      ${past.length ? "" : `<p class="muted">Nothing signed yet.</p>`}
      <ul class="history">${past
        .map((e) => `<li><span class="muted">${h(e.at)}</span> ${h(e.action)} for ${h(siteName(e.origin))}: ${h(e.summary)}</li>`)
        .join("")}</ul>
    </section>`;

  app.querySelector<HTMLFormElement>("#new")!.onsubmit = async (e) => {
    e.preventDefault();
    await newIdentity(new FormData(e.target as HTMLFormElement).get("label") as string);
    renderHome();
  };
  app.querySelectorAll<HTMLButtonElement>("[data-remove]").forEach((b) => {
    b.onclick = async () => {
      if (confirm("Delete this identity? Its key cannot be recovered.")) {
        await identities.remove(b.dataset.remove!);
        renderHome();
      }
    };
  });
  app.querySelectorAll<HTMLButtonElement>("[data-export]").forEach((b) => {
    b.onclick = async () => {
      const i = await identities.get(b.dataset.export!);
      if (!i?.certChainPem) return;
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([i.certChainPem], { type: "application/x-pem-file" }));
      a.download = `${i.label.replace(/\W+/g, "-").toLowerCase()}.chain.pem`;
      a.click();
    };
  });
}

// ------------------------------------------------------------------ requests

function reply(origin: string, message: Record<string, unknown>) {
  peer?.postMessage(message, origin);
}

function waiting(origin: string) {
  app.innerHTML = `
    <header><h1>Consent Wallet</h1><p class="muted">Connected to ${h(siteName(origin))}</p></header>
    <section class="center"><p>Waiting for ${h(siteName(origin))}…</p>
    ${sessionIdentity ? `<p class="muted">Signing as <strong>${h(sessionIdentity.label)}</strong></p>` : ""}</section>`;
}

/** Shows an approval card and resolves with the chosen identity, or null if declined. */
async function approve(
  origin: string,
  title: string,
  body: string,
  opts: { choose?: (all: Identity[]) => Identity[]; allowCreate?: boolean; approveLabel?: string } = {},
): Promise<Identity | null> {
  const all = await identities.all();
  const choices = sessionIdentity ? [sessionIdentity] : (opts.choose ?? ((a) => a))(all);
  app.innerHTML = `
    <header><h1>Consent Wallet</h1><p class="muted">Request from <strong>${h(siteName(origin))}</strong> (${h(origin)})</p></header>
    <section class="card request">
      <h2>${h(title)}</h2>
      ${body}
      <fieldset class="identities"><legend>Sign as</legend>
        ${choices
          .map(
            (i, n) => `<label class="identity"><input type="radio" name="identity" value="${h(i.id)}" ${n === 0 ? "checked" : ""} />
              <span><strong>${h(i.label)}</strong><span class="muted">${h(i.email ?? short(i.did))}</span></span></label>`,
          )
          .join("")}
        ${opts.allowCreate && !sessionIdentity
          ? `<label class="identity"><input type="radio" name="identity" value="__new" ${choices.length ? "" : "checked"} />
              <span><strong>New identity…</strong><span class="muted">Creates a new key in this wallet</span></span></label>`
          : ""}
      </fieldset>
      <input name="label" placeholder="Name for the new identity" hidden />
      ${!choices.length && !opts.allowCreate ? `<p class="warn">No identity in this wallet can answer this request.</p>` : ""}
      <div class="row actions">
        <button class="secondary" data-act="decline">Decline</button>
        <button data-act="approve" ${!choices.length && !opts.allowCreate ? "disabled" : ""}>${h(opts.approveLabel ?? "Approve")}</button>
      </div>
    </section>`;

  const label = app.querySelector<HTMLInputElement>("input[name=label]")!;
  const chosenId = () => app.querySelector<HTMLInputElement>("input[name=identity]:checked")?.value ?? "";
  const syncLabel = () => (label.hidden = chosenId() !== "__new");
  app.querySelectorAll<HTMLInputElement>("input[name=identity]").forEach((r) => (r.onchange = syncLabel));
  syncLabel();

  return new Promise((resolve) => {
    app.querySelector<HTMLButtonElement>("[data-act=decline]")!.onclick = () => resolve(null);
    app.querySelector<HTMLButtonElement>("[data-act=approve]")!.onclick = async () => {
      const id = chosenId();
      if (!id) return;
      const chosen = id === "__new" ? await newIdentity(label.value) : await identities.get(id);
      sessionIdentity = chosen ?? undefined;
      resolve(chosen ?? null);
    };
  });
}

function terms(consent: unknown): string {
  if (!consent || typeof consent !== "object") return "";
  return `<dl class="terms">${Object.entries(consent as Record<string, unknown>)
    .map(([k, v]) => `<dt>${h(k)}</dt><dd>${h(Array.isArray(v) ? v.join(", ") : v)}</dd>`)
    .join("")}</dl>`;
}

function assetBlock(asset: Record<string, unknown> | undefined): string {
  if (!asset) return "";
  return `<figure class="asset">
    ${asset.thumbnail ? `<img src="${h(asset.thumbnail)}" alt="" />` : ""}
    <figcaption>${h(asset.name)}<br /><span class="mono muted">sha256 ${h(asset.hash)}</span></figcaption>
  </figure>`;
}

async function handle(req: Request, origin: string): Promise<Record<string, unknown>> {
  switch (req.type) {
    case "connect": {
      const who = await approve(origin, "Sign in", `<p>${h(siteName(origin))} asks which identity you are using.</p>`, {
        choose: (all) => all.filter((i) => i.certChainPem),
        approveLabel: "Sign in",
      });
      if (!who) throw new Error("declined");
      await history.add({ at: now(), origin, identityId: who.id, action: "Signed in", summary: who.label });
      return {
        did: who.did,
        email: who.email,
        certChainPem: who.certChainPem,
        signature: await signChallenge(who.keys.privateKey, "consent-demo-login", String(req.challenge)),
      };
    }

    case "certificate:request": {
      const who = await approve(
        origin,
        "Request a certificate",
        `<p>The Certificate site will certify that this identity belongs to <strong>${h(req.email)}</strong>.</p>
         <p class="muted">Only the public key leaves this wallet.</p>`,
        { choose: (all) => all.filter((i) => !i.certChainPem), allowCreate: true, approveLabel: "Send public key" },
      );
      if (!who) throw new Error("declined");
      return {
        did: who.did,
        publicKey: who.publicKey,
        signature: await signChallenge(who.keys.privateKey, "certificate-request", String(req.challenge)),
      };
    }

    case "certificate:deliver": {
      if (!sessionIdentity) throw new Error("no certificate request in this session");
      Object.assign(sessionIdentity, {
        certChainPem: String(req.certChainPem),
        email: String(req.email),
        certIssuer: String(req.issuer ?? ""),
      });
      await identities.put(sessionIdentity);
      await history.add({ at: now(), origin, identityId: sessionIdentity.id, action: "Installed certificate", summary: String(req.email) });
      return { did: sessionIdentity.did };
    }

    case "credential:sign": {
      const credential = req.credential as Record<string, unknown>;
      const subject = (credential.credentialSubject ?? {}) as Record<string, unknown>;
      const role = req.role === "issuer" ? "issuer" : "participant";
      const subjectId = String(subject.id ?? "");
      const fits = (i: Identity) =>
        role === "issuer"
          ? i.did === credential.issuer
          : subjectId.startsWith("mailto:")
            ? i.email?.toLowerCase() === subjectId.slice(7).toLowerCase()
            : i.did === subjectId;
      const who = await approve(
        origin,
        role === "issuer" ? "Sign the consent request" : "Give consent",
        `<p>${
          role === "issuer"
            ? `You are asking <strong>${h(req.counterparty ?? subjectId.replace(/^mailto:/, ""))}</strong> for consent to use this file:`
            : `<strong>${h(req.counterparty ?? short(String(credential.issuer)))}</strong> asks for your consent to use this file:`
        }</p>
         ${assetBlock(req.asset as Record<string, unknown>)}
         <h3>Public terms</h3>${terms(subject.consent)}
         ${req.agreementText ? `<h3>Private agreement</h3><pre class="agreement">${h(req.agreementText)}</pre>
           <p class="muted">Only a salted hash of the private agreement goes in the file.</p>` : ""}`,
        { choose: (all) => all.filter(fits), approveLabel: role === "issuer" ? "Sign" : "I consent" },
      );
      if (!who) throw new Error("declined");
      if (!fits(who)) throw new Error("this identity is not the one named in the credential");
      const proof = await createProof(credential, who.keys.privateKey, fromB64(who.publicKey), now());
      await history.add({
        at: now(),
        origin,
        identityId: who.id,
        action: role === "issuer" ? "Signed consent request" : "Gave consent",
        summary: String((req.asset as Record<string, unknown>)?.name ?? credential.id),
      });
      return { proof };
    }

    case "identity:sign": {
      // The CAWG identity assertion signature over the final manifest. The
      // wallet checks that what it signs covers the consent assertion whose
      // hash the site reports, then signs those bytes as-is.
      const who = sessionIdentity;
      if (!who?.certChainPem) throw new Error("sign the consent credential in this session first");
      const toBeSigned = fromB64(String(req.toBeSigned));
      const covers =
        containsBytes(toBeSigned, new TextEncoder().encode("cawg.consent")) &&
        containsBytes(toBeSigned, fromB64(String(req.consentHash)));
      if (!covers) throw new Error("the identity signature does not cover the consent assertion");
      const ok = await approve(
        origin,
        "Attach your identity to the file",
        `<p>Consent-O-Tron is writing the file. This signs your CAWG identity assertion, which covers your consent.</p>
         ${assetBlock(req.asset as Record<string, unknown>)}`,
        { approveLabel: "Sign identity" },
      );
      if (!ok) throw new Error("declined");
      const signature = b64(await signBytes(who.keys.privateKey, toBeSigned));
      await history.add({ at: now(), origin, identityId: who.id, action: "Signed identity assertion", summary: String((req.asset as Record<string, unknown>)?.name ?? "") });
      return { signature };
    }

    case "registry:request": {
      // Ask a trust registry for a permission, signing the challenge bound to
      // that exact permission (the registry's proof-of-possession format).
      const permission = req.permission as { authority_id: string; action: string; resource: string };
      const entityId = String(req.entityId ?? "");
      const who = await approve(
        origin,
        "Request permission",
        `<p>${h(siteName(origin))} will record that you asked for this permission. A guild administrator decides.</p>
         <dl class="terms"><dt>Action</dt><dd>${h(permission.action)}</dd><dt>Credential</dt><dd>${h(permission.resource)}</dd>
         <dt>Authority</dt><dd class="mono">${h(permission.authority_id)}</dd></dl>`,
        { choose: (all) => all.filter((i) => i.did === entityId && i.certChainPem), approveLabel: "Sign request" },
      );
      if (!who) throw new Error("declined");
      if (who.did !== entityId) throw new Error("this identity is not the one signed in to the registry");
      const signature = b64(await signBytes(who.keys.privateKey, accessRequestMessage(String(req.challenge), who.did, permission)));
      await history.add({ at: now(), origin, identityId: who.id, action: "Requested permission", summary: `${permission.action} ${permission.resource}` });
      return { did: who.did, signature };
    }

    default:
      throw new Error(`unknown request ${req.type}`);
  }
}

function startRequestMode() {
  let busy = Promise.resolve();
  window.addEventListener("message", (e: MessageEvent) => {
    if (!ALLOWED_ORIGINS.has(e.origin) || e.source !== peer) return;
    const req = e.data as Request;
    if (!req || typeof req.type !== "string" || typeof req.id !== "string") return;
    busy = busy.then(async () => {
      try {
        reply(e.origin, { id: req.id, type: `${req.type}:result`, ...(await handle(req, e.origin)) });
      } catch (err) {
        reply(e.origin, { id: req.id, type: "error", message: err instanceof Error ? err.message : String(err) });
      }
      waiting(e.origin);
    });
  });
  app.innerHTML = `<header><h1>Consent Wallet</h1></header><section class="center"><p>Connecting…</p></section>`;
  // The peer's origin is not known until its first message, so "ready"
  // carries nothing and goes to any origin.
  peer!.postMessage({ type: "ready" }, "*");
}

if (inRequestMode) startRequestMode();
else renderHome();
