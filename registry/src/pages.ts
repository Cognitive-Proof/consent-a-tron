import type { AccessRequest, AuditEvent, Grant } from "@cognitiveproof/cawg-trqp-plugin-admin";
import { AUTHORITY_ID, CERT_SITE_URL, CONSENT_SITE_URL, CREDENTIAL_TYPE, ISSUE, REGISTRY_URL } from "./config.js";
import type { Email } from "./mail.js";

export interface Session {
  did: string;
  email: string;
  admin: boolean;
}

export function esc(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/** JSON for embedding in a <script> element. */
const scriptJson = (value: unknown) => JSON.stringify(value).replace(/</g, "\\u003c");

export function layout(title: string, body: string, session?: Session | null): string {
  const nav = session
    ? `<span class="muted">${esc(session.email)}${session.admin ? " · admin" : ""}</span> <a href="/request">My access</a>${session.admin ? ' <a href="/admin">Admin</a>' : ""} <a href="/logout">Sign out</a>`
    : `<a href="/request">Request access</a> <a href="/admin">Admin</a>`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${esc(title)} · Trust Registry</title><link rel="stylesheet" href="/static/style.css" /></head>
<body class="registry"><main>
<header><div class="row"><div class="site"><a href="/" style="color:inherit;text-decoration:none">Guild Trust Registry</a></div><nav class="row" style="gap:12px">${nav}</nav></div><h1>${esc(title)}</h1></header>
${body}
<p class="muted" style="margin-top:48px;font-size:13px">Test environment · <a href="/governance">Governance framework</a> · <a href="/outbox">Sent emails</a></p>
</main></body></html>`;
}

const SIGN_IN = `<div class="card"><p>Sign in with your wallet. You need a certificate from the <a href="${esc(CERT_SITE_URL)}">Certificate site</a>.</p>
<div class="row actions"><button id="signin">Sign in with wallet</button></div><p id="status" class="muted"></p></div>
<script type="module">
import { WalletSession, postJson } from "/static/wallet-client.js";
const status = document.getElementById("status");
document.getElementById("signin").onclick = async () => {
  const wallet = new WalletSession();
  try {
    await wallet.open();
    const { challenge } = await (await fetch("/api/challenge", { method: "POST" })).json();
    status.textContent = "Choose an identity in your wallet…";
    const who = await wallet.request("connect", { challenge });
    await postJson("/api/login", { challenge, ...who });
    wallet.close();
    location.reload();
  } catch (err) { status.textContent = err.message; wallet.close(); }
};
</script>`;

export function signInPage(title: string, intro: string): string {
  return layout(title, `<p>${intro}</p>${SIGN_IN}`);
}

export function homePage(session: Session | null): string {
  return layout(
    "Who may ask for consent",
    `<p>This registry records which producers the guild has authorized to issue its likeness consent credential. Verifiers ask it, using the Trust Registry Query Protocol (TRQP), whether a credential's issuer was authorized when the credential was signed.</p>
<div class="card"><dl class="terms">
<dt>Authority</dt><dd class="mono">${esc(AUTHORITY_ID)}</dd>
<dt>Credential</dt><dd>${esc(CREDENTIAL_TYPE)}</dd>
<dt>TRQP endpoint</dt><dd class="mono">POST ${esc(REGISTRY_URL)}/authorization</dd>
<dt>DID document</dt><dd><a href="/.well-known/did.json">/.well-known/did.json</a></dd>
</dl></div>
<div class="row" style="justify-content:flex-start"><a class="button" href="/request">Request permission to issue</a>${session?.admin ? '<a class="button secondary" href="/admin">Review requests</a>' : ""}</div>
<h2>How it works</h2>
<ol>
<li>A producer gets a certificate on the <a href="${esc(CERT_SITE_URL)}">Certificate site</a>, then asks here for permission to issue, signing the request with their wallet.</li>
<li>A guild administrator reviews the request and approves or rejects it. Permission can be revoked later.</li>
<li><a href="${esc(CONSENT_SITE_URL)}">Consent-o-tron</a> checks this registry before accepting a credential. A revocation stops new credentials; consent signed while the producer was authorized stays valid.</li>
</ol>`,
    session,
  );
}

const statusBadge = (status: string) =>
  `<span class="badge ${status === "approved" || status === "active" ? "ok" : status === "rejected" || status === "revoked" ? "fail" : ""}">${esc(status)}</span>`;

export function requestPage(session: Session, requests: AccessRequest[], grants: Grant[]): string {
  const active = grants.find((g) => g.revoked_at === null);
  const pending = requests.find((r) => r.status === "pending");
  const history = requests
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .map(
      (r) => `<li><div class="row"><span>Requested ${esc(r.created_at)}</span>${statusBadge(r.status)}</div>
${r.decision_note ? `<div class="muted">${esc(r.decided_by)}: ${esc(r.decision_note)}</div>` : ""}</li>`,
    )
    .join("");

  let action: string;
  if (active) {
    action = `<p class="notice">You are authorized to issue ${esc(CREDENTIAL_TYPE)} since ${esc(active.granted_at)}.</p>`;
  } else if (pending) {
    action = `<p class="notice">Your request is waiting for a guild administrator.</p>`;
  } else {
    action = `<form class="card" id="request">
<h2>Request permission to issue</h2>
<p class="muted">You'll sign the request with your wallet, proving you hold the key for ${esc(session.email)}.</p>
<label>Your name<input name="name" required /></label>
<label>Organization<input name="organization" required placeholder="Production company or studio" /></label>
<label>Why do you need to issue consent credentials?<textarea name="note" rows="3"></textarea></label>
<div class="row actions"><button>Sign and submit</button></div><p id="status" class="muted"></p></form>
<script type="module">
import { WalletSession, postJson } from "/static/wallet-client.js";
const permission = ${scriptJson(ISSUE)}, email = ${scriptJson(session.email)}, did = ${scriptJson(session.did)};
const form = document.getElementById("request"), status = document.getElementById("status");
form.onsubmit = async (e) => {
  e.preventDefault();
  const applicant = Object.fromEntries(new FormData(form));
  const wallet = new WalletSession();
  try {
    await wallet.open();
    const { challenge } = await (await fetch("/api/challenge", { method: "POST" })).json();
    status.textContent = "Approve the request in your wallet…";
    const signed = await wallet.request("registry:request", { challenge, permission, entityId: did });
    await postJson("/api/requests", { challenge, signature: signed.signature, applicant: { ...applicant, email } });
    wallet.close();
    location.reload();
  } catch (err) { status.textContent = err.message; wallet.close(); }
};
</script>`;
  }

  return layout(
    "Permission to issue",
    `<div class="card"><dl class="terms"><dt>Signed in as</dt><dd>${esc(session.email)}</dd><dt>Identifier</dt><dd class="mono">${esc(session.did)}</dd></dl></div>
${action}
${history ? `<h2>Your requests</h2><ul class="history">${history}</ul>` : ""}`,
    session,
  );
}

const ADMIN_SCRIPT = `<script type="module">
import { postJson } from "/static/wallet-client.js";
for (const button of document.querySelectorAll("[data-act]")) {
  button.onclick = async () => {
    const card = button.closest("[data-id]");
    const note = card.querySelector("textarea")?.value || null;
    const [kind, act] = button.dataset.act.split(":");
    if (act === "revoke" && !confirm("Revoke this permission? Credentials signed from now on will fail verification.")) return;
    button.disabled = true;
    try {
      await postJson("/api/admin/" + kind + "/" + card.dataset.id + "/" + act, kind === "grants" ? { reason: note } : { note });
      location.reload();
    } catch (err) { alert(err.message); button.disabled = false; }
  };
}
</script>`;

export function adminPage(session: Session, pending: AccessRequest[], grants: Grant[], audit: AuditEvent[]): string {
  const requests = pending
    .map(
      (r) => `<article class="card" data-id="${esc(r.id)}">
<div class="row"><strong>${esc(r.applicant.name)} · ${esc(r.applicant.organization)}</strong><span class="muted">${esc(r.created_at)}</span></div>
<div>${esc(r.applicant.email)}</div><div class="mono muted">${esc(r.entity_id)}</div>
${r.applicant.note ? `<p>${esc(r.applicant.note)}</p>` : ""}
<div class="muted" style="font-size:13px">Evidence: ${r.evidence.map(esc).join(" · ")}</div>
<label>Note (optional)<textarea rows="2"></textarea></label>
<div class="row actions"><button class="secondary danger" data-act="requests:reject">Reject</button><button data-act="requests:approve">Approve</button></div>
</article>`,
    )
    .join("");
  const grantRows = grants
    .sort((a, b) => b.granted_at.localeCompare(a.granted_at))
    .map(
      (g) => `<article class="card" data-id="${esc(g.id)}">
<div class="row"><strong>${esc(g.action)}</strong>${statusBadge(g.revoked_at ? "revoked" : "active")}</div>
<div class="mono muted">${esc(g.entity_id)}</div>
<div class="muted">Granted ${esc(g.granted_at)} by ${esc(g.granted_by)}${g.revoked_at ? ` · revoked ${esc(g.revoked_at)} by ${esc(g.revoked_by)}` : ""}</div>
${g.revoked_at ? "" : `<label>Reason (optional)<textarea rows="1"></textarea></label><div class="row actions"><button class="secondary danger" data-act="grants:revoke">Revoke</button></div>`}
</article>`,
    )
    .join("");
  const log = audit
    .sort((a, b) => b.at.localeCompare(a.at))
    .slice(0, 30)
    .map((e) => `<li><span class="muted">${esc(e.at)}</span> ${esc(e.action)} by ${esc(e.actor)} · <span class="mono">${esc(e.entity_id.slice(0, 24))}…</span></li>`)
    .join("");
  return layout(
    "Review requests",
    `<h2>Pending</h2>${requests || '<p class="muted">No pending requests.</p>'}
<h2>Grants</h2>${grantRows || '<p class="muted">No grants yet.</p>'}
<h2>Audit log</h2><ul class="history">${log}</ul>${ADMIN_SCRIPT}`,
    session,
  );
}

export function governancePage(): string {
  return layout(
    "Governance framework",
    `<p class="notice">A demonstration governance framework for an example actors' guild. It is not a real policy.</p>
<dl class="terms card">
<dt>Authority</dt><dd class="mono">${esc(AUTHORITY_ID)}</dd>
<dt>Credential</dt><dd>${esc(CREDENTIAL_TYPE)}</dd>
<dt>Query protocol</dt><dd>TRQP 2.0, <span class="mono">POST ${esc(REGISTRY_URL)}/authorization</span></dd>
</dl>
<h2>Actions</h2>
<dl class="terms"><dt>issue</dt><dd>Ask for consent and issue ${esc(CREDENTIAL_TYPE)}. Granted to producers a guild administrator approves.</dd>
<dt>publish-status</dt><dd>Publish the status lists that record withdrawn consent. Granted to Consent-o-tron's service key.</dd></dl>
<h2>Rules</h2>
<ol>
<li>An applicant must hold a CAWG certificate from the Certificate site for the email they apply with, and sign the request with that certificate's key.</li>
<li>Administrators approve or reject each request. Every decision is recorded.</li>
<li>Revocation applies from the moment it is recorded. A credential signed while its issuer was authorized remains valid; verifiers ask with the credential's signing time.</li>
</ol>`,
  );
}

export function outboxPage(emails: Email[], usesResend: boolean): string {
  const items = emails
    .map(
      (e) => `<article class="card"><div class="row"><strong>${esc(e.subject)}</strong><span class="badge ${e.delivery === "resend" ? "ok" : ""}">${e.delivery === "resend" ? "sent via Resend" : "outbox only"}</span></div>
<div class="muted">To ${esc(e.to)} · ${esc(e.at)}</div><p>${esc(e.body)}</p><a class="button" href="${esc(e.link)}">Open link</a></article>`,
    )
    .join("");
  return layout(
    "Sent emails",
    `<p class="notice">${usesResend ? "Emails are sent through Resend and also listed here." : "RESEND_API_KEY is not set, so emails are only listed here."}</p>${items || '<p class="muted">No emails yet.</p>'}`,
  );
}
