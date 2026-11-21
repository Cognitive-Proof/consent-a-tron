// The guild's trust registry (http://localhost:4005).
//
// TRQP queries (POST /authorization, /recognition) are answered by the
// cawg-trqp core's HTTPTRQPService from the grants that the admin plugin
// manages; that plugin's AdminPolicyService honours context.time, so a
// revocation is not retroactive. Producers sign in with their Consent Wallet
// (CAWG certificate required), request permission to issue, and guild
// administrators (REGISTRY_ADMIN_EMAILS) approve, reject and revoke.

import { createPrivateKey, createPublicKey, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { HTTPTRQPService } from "@cognitiveproof/cawg-trqp";
import {
  AdminError,
  AdminPolicyService,
  DidKeyProofVerifier,
  MongoAdminStore,
  RegistryAdmin,
  type AccessRequest,
} from "@cognitiveproof/cawg-trqp-plugin-admin";
import { createAdminRouter } from "@cognitiveproof/cawg-trqp-plugin-admin/router";
import type { NextFunction, Request, Response } from "express";
import { MongoClient } from "mongodb";
import { verifyCertificate } from "./certs.js";
import {
  ADMIN_EMAILS,
  APP_ROOT,
  AUTHORITY_ID,
  ISSUE,
  LISTEN_HOST,
  LISTEN_PORT,
  MONGODB_DB,
  MONGODB_URI,
  PUBLISH_STATUS,
  REGISTRY_URL,
  WALLET_URL,
  pki,
} from "./config.js";
import { Mailer, type Email } from "./mail.js";
import { adminPage, esc, governancePage, homePage, layout, outboxPage, requestPage, signInPage, type Session } from "./pages.js";

// ------------------------------------------------------------------ storage

const mongo = await new MongoClient(MONGODB_URI).connect().catch((err) => {
  console.error(`cannot reach MongoDB at ${MONGODB_URI}: ${err.message}`);
  process.exit(1);
});
const db = mongo.db(MONGODB_DB);
const sessions = db.collection<{ _id: string; did: string; email: string; created_at: string }>("registry_sessions");
const certificates = db.collection<{ _id: string; email: string; fingerprint: string; verified_at: string }>("registry_certificates");
const mailer = new Mailer(db.collection<Email>("outbox"));

const store = new MongoAdminStore({
  uri: MONGODB_URI,
  dbName: MONGODB_DB,
  grantsCollection: "registry_grants",
  requestsCollection: "registry_requests",
  challengesCollection: "registry_challenges",
  auditCollection: "registry_audit",
});

const CAWG_ROOT = pki("cawg-root.pem");
const loginVerifier = new DidKeyProofVerifier();

const admin = new RegistryAdmin({
  store,
  requestable: [ISSUE],
  policyEpoch: "guild-consent-v1",
  // An applicant must have signed in with a CAWG certificate for the email
  // they apply with; sign-in verified it and recorded it against their DID.
  checkApplicant: async (input) => {
    const cert = await certificates.findOne({ _id: input.entity_id });
    if (!cert) throw new AdminError(403, "Certificate required", "Sign in with a wallet identity that has a CAWG certificate");
    if ((input.applicant?.email ?? "").toLowerCase() !== cert.email) {
      throw new AdminError(403, "Email mismatch", `This identity's certificate is for ${cert.email}`);
    }
    return [`cawg-certificate:${cert.email}`, `certificate-sha256:${cert.fingerprint}`];
  },
});

// ------------------------------------------------------------------ helpers

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function didKeyFromPem(privateKeyPem: string): string {
  const x = createPublicKey(createPrivateKey(privateKeyPem)).export({ format: "jwk" }).x as string;
  let n = 0n;
  for (const b of [0xed, 0x01, ...Buffer.from(x, "base64url")]) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) {
    out = BASE58[Number(n % 58n)] + out;
    n /= 58n;
  }
  return `did:key:z${out}`;
}

function cookie(req: Request, name: string): string | null {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

async function currentSession(req: Request): Promise<Session | null> {
  const token = cookie(req, "reg");
  if (!token) return null;
  const s = await sessions.findOne({ _id: token });
  return s ? { did: s.did, email: s.email, admin: ADMIN_EMAILS.has(s.email) } : null;
}

type Handler = (req: Request, res: Response) => Promise<void>;
const wrap = (fn: Handler) => (req: Request, res: Response, next: NextFunction) => fn(req, res).catch(next);

function problem(res: Response, status: number, title: string, detail: string): void {
  res.status(status).contentType("application/problem+json").json({ type: "about:blank", title, status, detail });
}

const staticFile = (relative: string) => readFileSync(join(APP_ROOT, relative), "utf8");

// ------------------------------------------------------------------ app

const service = new HTTPTRQPService(new AdminPolicyService({ store }));
const app = service.app;

app.get("/static/style.css", (_req, res) => {
  res.type("text/css").send(staticFile("wallet/src/style.css"));
});
app.get("/static/wallet-client.js", (_req, res) => {
  res.type("text/javascript").send(staticFile("crates/demo-common/src/wallet-client.js").replace("__WALLET_ORIGIN__", WALLET_URL));
});

// The authority's DID document: discoverable governance framework and TRQP endpoint (TRQP 2.0 §authority_id).
app.get("/.well-known/did.json", (_req, res) => {
  res.json({
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: AUTHORITY_ID,
    service: [
      { id: `${AUTHORITY_ID}#trqp`, type: "TrustRegistryQueryProtocol", serviceEndpoint: REGISTRY_URL },
      { id: `${AUTHORITY_ID}#governance`, type: "GovernanceFramework", serviceEndpoint: `${REGISTRY_URL}/governance` },
    ],
  });
});

app.get("/", wrap(async (req, res) => void res.send(homePage(await currentSession(req)))));
app.get("/governance", (_req, res) => void res.send(governancePage()));
app.get("/outbox", wrap(async (_req, res) => void res.send(outboxPage(await mailer.recent(), mailer.usesResend))));

app.get(
  "/request",
  wrap(async (req, res) => {
    const session = await currentSession(req);
    if (!session) {
      res.send(signInPage("Permission to issue", "Producers ask here for permission to issue the guild's consent credential."));
      return;
    }
    const [requests, grants] = await Promise.all([
      admin.listRequests({ entity_id: session.did, authority_id: AUTHORITY_ID }),
      admin.listGrants({ entity_id: session.did, ...ISSUE }),
    ]);
    res.send(requestPage(session, requests, grants));
  }),
);

app.get(
  "/admin",
  wrap(async (req, res) => {
    const session = await currentSession(req);
    if (!session) {
      res.send(signInPage("Review requests", "Guild administrators sign in with their wallet."));
      return;
    }
    if (!session.admin) {
      res.status(403).send(layout("Review requests", `<p class="notice warn">${esc(session.email)} is not a registry administrator.</p>`, session));
      return;
    }
    const [pending, grants, audit] = await Promise.all([
      admin.listRequests({ status: "pending" }),
      admin.listGrants({ authority_id: AUTHORITY_ID }),
      admin.auditLog(),
    ]);
    res.send(adminPage(session, pending, grants, audit));
  }),
);

app.get(
  "/logout",
  wrap(async (req, res) => {
    const token = cookie(req, "reg");
    if (token) await sessions.deleteOne({ _id: token });
    res.setHeader("Set-Cookie", "reg=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
    res.redirect("/");
  }),
);

// A challenge for sign-in or for an access request; both consume it.
app.post(
  "/api/challenge",
  wrap(async (_req, res) => {
    const challenge = await admin.createChallenge();
    res.json({ challenge: challenge.id, expires_at: challenge.expires_at });
  }),
);

app.post(
  "/api/login",
  wrap(async (req, res) => {
    const { challenge, did, certChainPem, signature } = req.body ?? {};
    if (typeof challenge !== "string" || typeof did !== "string" || typeof signature !== "string") {
      return problem(res, 400, "Bad Request", "challenge, did and signature are required");
    }
    const taken = await store.takeChallenge(challenge);
    if (!taken || taken.expires_at <= new Date().toISOString()) return problem(res, 400, "Invalid challenge", "The challenge is unknown, used, or expired");
    const ok = await loginVerifier.verify(did, new TextEncoder().encode(`consent-demo-login:${challenge}`), Buffer.from(signature, "base64"));
    if (!ok) return problem(res, 403, "Signature invalid", "The wallet signature does not verify");
    if (typeof certChainPem !== "string") return problem(res, 403, "Certificate required", "This identity has no certificate yet; get one on the Certificate site");
    let cert;
    try {
      cert = verifyCertificate(certChainPem, CAWG_ROOT, did);
    } catch (err) {
      return problem(res, 403, "Certificate not accepted", (err as Error).message);
    }
    const now = new Date().toISOString();
    await certificates.updateOne({ _id: did }, { $set: { email: cert.email, fingerprint: cert.fingerprint, verified_at: now } }, { upsert: true });
    const token = randomUUID();
    await sessions.insertOne({ _id: token, did, email: cert.email, created_at: now });
    const secure = REGISTRY_URL.startsWith("https:") ? "; Secure" : "";
    res.setHeader("Set-Cookie", `reg=${token}; Path=/; HttpOnly; SameSite=Lax${secure}`);
    res.json({ ok: true, admin: ADMIN_EMAILS.has(cert.email) });
  }),
);

app.post(
  "/api/requests",
  wrap(async (req, res) => {
    const session = await currentSession(req);
    if (!session) return problem(res, 401, "Unauthorized", "Sign in first");
    const { challenge, signature, applicant } = req.body ?? {};
    const request = await admin.requestAccess({ entity_id: session.did, ...ISSUE, challenge, signature, applicant });
    for (const to of ADMIN_EMAILS) {
      await mailer.send(
        to,
        `Registry request from ${request.applicant.organization ?? session.email}`,
        `${request.applicant.name ?? session.email} (${session.email}) asked for permission to issue consent credentials.`,
        `${REGISTRY_URL}/admin`,
      );
    }
    res.status(201).json(request);
  }),
);

async function notifyApplicant(request: AccessRequest, subject: string, body: string) {
  if (request.applicant.email) await mailer.send(request.applicant.email, subject, body, `${REGISTRY_URL}/request`);
}

// Admin actions from the pages; the plugin router below offers the same over its own API.
const requireAdmin = async (req: Request, res: Response): Promise<Session | null> => {
  const session = await currentSession(req);
  if (!session?.admin) {
    problem(res, 403, "Forbidden", "Registry administrators only");
    return null;
  }
  return session;
};

app.post(
  "/api/admin/requests/:id/approve",
  wrap(async (req, res) => {
    const session = await requireAdmin(req, res);
    if (!session) return;
    const result = await admin.approve(req.params.id, session.email, req.body?.note ?? null);
    await notifyApplicant(result.request, "You can now issue consent credentials", "The guild approved your request to issue its likeness consent credential.");
    res.json(result);
  }),
);

app.post(
  "/api/admin/requests/:id/reject",
  wrap(async (req, res) => {
    const session = await requireAdmin(req, res);
    if (!session) return;
    const request = await admin.reject(req.params.id, session.email, req.body?.note ?? null);
    await notifyApplicant(request, "Your registry request was declined", request.decision_note ?? "The guild declined your request to issue consent credentials.");
    res.json(request);
  }),
);

app.post(
  "/api/admin/grants/:id/revoke",
  wrap(async (req, res) => {
    const session = await requireAdmin(req, res);
    if (!session) return;
    const grant = await admin.revoke(req.params.id, session.email, req.body?.reason ?? null);
    const request = grant.request_id ? await admin.getRequest(grant.request_id) : null;
    if (request) await notifyApplicant(request, "Your permission to issue was revoked", "Consent credentials you sign from now on will not verify. Credentials signed before now are unaffected.");
    res.json(grant);
  }),
);

// The plugin's HTTP API, for programmatic use. Administrators are identified by their wallet session.
app.use(
  "/registry",
  createAdminRouter(admin, {
    authenticateAdmin: async (req) => {
      const session = await currentSession(req);
      return session?.admin ? session.email : null;
    },
  }),
);

app.use((err: unknown, _req: Request, res: Response, next: NextFunction) => {
  if (res.headersSent) return next(err);
  if (err instanceof AdminError) return problem(res, err.status, err.title, err.message);
  console.error("registry_error", err);
  problem(res, 500, "Internal Server Error", "The registry could not complete the request");
});

// Consent-o-tron's service key publishes the status lists that record withdrawn consent.
const statusPublisher = didKeyFromPem(pki("consent-o-tron.key"));
await admin.grantDirectly(statusPublisher, PUBLISH_STATUS, "system", ["service:consent-o-tron-status-lists"]);

app.listen(LISTEN_PORT, LISTEN_HOST, () => {
  console.log(
    `Trust registry on ${REGISTRY_URL}  (authority ${AUTHORITY_ID}, admins: ${[...ADMIN_EMAILS].join(", ") || "none"}, email: ${mailer.usesResend ? "Resend" : "outbox only"})`,
  );
});
