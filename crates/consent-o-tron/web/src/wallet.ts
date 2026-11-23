// The Consent Wallet flows. The client itself is served by consent-o-tron
// at /static/wallet-client.js, with the wallet's origin filled in, so it is
// loaded at runtime rather than bundled.

import { getJson, postJson, type AgreementView, type Stage, type User } from "./api";

type WalletSession = {
  open(): Promise<void>;
  request<T = any>(type: string, payload?: object): Promise<T>;
  close(): void;
};

const CLIENT_URL = "/static/wallet-client.js";
let client: Promise<{ WalletSession: new () => WalletSession }> | null = null;

/** Opens the wallet dialog, runs `fn`, and always closes the dialog. */
async function withWallet<T>(fn: (wallet: WalletSession) => Promise<T>): Promise<T> {
  client ??= import(/* @vite-ignore */ CLIENT_URL);
  const { WalletSession } = await client;
  const wallet = new WalletSession();
  try {
    await wallet.open();
    return await fn(wallet);
  } finally {
    wallet.close();
  }
}

/** Signs in with a wallet identity; its certificate gives the email. */
export function logIn(): Promise<User> {
  return withWallet(async (wallet) => {
    const { challenge } = await getJson<{ challenge: string }>("/api/challenge");
    const who = await wallet.request("connect", { challenge });
    return postJson<User>("/api/login", { challenge, ...who });
  });
}

/** The producer signs the credential as issuer; the server then emails the person consenting. */
export function signAsProducer(a: AgreementView): Promise<void> {
  return withWallet(async (wallet) => {
    const { proof } = await wallet.request("credential:sign", {
      credential: a.credential,
      role: "issuer",
      asset: a.walletAsset,
      agreementText: a.agreementText,
      counterparty: a.cosignerEmail,
    });
    await postJson(`/api/a/${a.id}/producer-proof`, { proof });
  });
}

/** Either party withdraws, signing with the key they signed the credential with. */
export function withdraw(a: AgreementView): Promise<void> {
  return withWallet(async (wallet) => {
    const { challenge } = await getJson<{ challenge: string }>("/api/challenge");
    const { did, signature } = await wallet.request("consent:withdraw", {
      challenge,
      credentialId: (a.credential as { id: string }).id,
      signer: a.signerDid,
      asset: a.walletAsset,
    });
    await postJson(`/api/a/${a.id}/withdraw`, { challenge, did, signature });
  });
}

export type ConsentStep = "connect" | "consent" | "authoring" | "identity" | "done";

/** Waits for the file to be written, signing the identity assertion when it's asked for. */
async function authorFile(wallet: WalletSession, a: AgreementView, invite: string, onStep: (step: ConsentStep) => void) {
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  onStep("authoring");
  for (;;) {
    const s = await getJson<{ stage: Stage; error?: string; identityRequest?: object }>(
      `/api/a/${a.id}/status?invite=${encodeURIComponent(invite)}`,
    );
    if (s.identityRequest) {
      onStep("identity");
      const { signature } = await wallet.request("identity:sign", { ...s.identityRequest, asset: a.walletAsset });
      await postJson(`/api/a/${a.id}/identity-signature`, { invite, signature });
      onStep("authoring");
    }
    if (s.stage === "signed") break;
    if (s.stage === "failed") throw new Error(s.error || "writing the file failed");
    await sleep(600);
  }
  onStep("done");
}

/**
 * A license has one signer: the producer connects, signs the credential
 * about their own file, then signs the CAWG identity assertion.
 */
export function licenseFile(a: AgreementView, onStep: (step: ConsentStep) => void = () => {}): Promise<void> {
  return withWallet(async (wallet) => {
    onStep("connect");
    const { challenge } = await getJson<{ challenge: string }>("/api/challenge");
    const who = await wallet.request("connect", { challenge });
    onStep("consent");
    const { proof } = await wallet.request("credential:sign", {
      credential: a.credential,
      role: "licensor",
      asset: a.walletAsset,
      agreementText: a.agreementText,
    });
    const { invite } = await postJson<{ invite: string }>(`/api/a/${a.id}/license`, { challenge, ...who, proof });
    await authorFile(wallet, a, invite, onStep);
  });
}

/**
 * The person consenting connects, signs the credential as participant, and
 * then signs the CAWG identity assertion while the file is written.
 */
export function consent(a: AgreementView, onStep: (step: ConsentStep) => void): Promise<void> {
  const invite = a.invite!;
  return withWallet(async (wallet) => {
    onStep("connect");
    const { challenge } = await getJson<{ challenge: string }>("/api/challenge");
    const who = await wallet.request("connect", { challenge });
    await postJson(`/api/a/${a.id}/cosigner`, { invite, challenge, ...who });
    onStep("consent");
    const { proof } = await wallet.request("credential:sign", {
      credential: a.credential,
      role: "participant",
      asset: a.walletAsset,
      agreementText: a.agreementText,
      counterparty: a.producerEmail,
    });
    await postJson(`/api/a/${a.id}/participant-proof`, { invite, proof });
    await authorFile(wallet, a, invite, onStep);
  });
}
