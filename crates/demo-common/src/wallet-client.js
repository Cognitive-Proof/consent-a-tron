// Talks to the Consent Wallet (see wallet/src/main.ts for the protocol).
//
// The wallet opens in a dialog over this page, in an iframe. Its keys live
// in the wallet origin's IndexedDB, which an embedded frame can reach only
// when this page and the wallet are the same site: localhost:* here, or
// subdomains of one domain when deployed.

// Filled in by the server from WALLET_URL.
export const WALLET_ORIGIN = "__WALLET_ORIGIN__";

export class WalletSession {
  constructor() {
    this.pending = new Map();
    this.onMessage = (e) => {
      if (e.origin !== WALLET_ORIGIN || e.source !== this.win) return;
      const msg = e.data || {};
      if (msg.type === "ready") return this.readyResolve?.();
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      msg.type === "error" ? p.reject(new Error(msg.message)) : p.resolve(msg);
    };
    window.addEventListener("message", this.onMessage);
  }

  open() {
    this.ready = new Promise((resolve) => (this.readyResolve = resolve));
    const dialog = document.createElement("dialog");
    dialog.className = "wallet-dialog";
    dialog.innerHTML = `<div class="wallet-bar"><span>Consent Wallet</span><button class="link" type="button">Close</button></div>
      <iframe src="${WALLET_ORIGIN}/?request" title="Consent Wallet"></iframe>`;
    dialog.querySelector("button").onclick = () => this.cancel();
    dialog.addEventListener("cancel", (e) => {
      e.preventDefault();
      this.cancel();
    });
    document.body.append(dialog);
    dialog.showModal();
    this.dialog = dialog;
    this.win = dialog.querySelector("iframe").contentWindow;
    return this.ready;
  }

  request(type, payload = {}) {
    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.win.postMessage({ id, type, ...payload }, WALLET_ORIGIN);
    });
  }

  /** Closing the dialog declines whatever is pending. */
  cancel() {
    for (const p of this.pending.values()) p.reject(new Error("Wallet closed"));
    this.pending.clear();
    this.close();
  }

  close() {
    this.dialog?.remove();
    this.dialog = null;
    window.removeEventListener("message", this.onMessage);
  }
}

export async function postJson(url, body) {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const text = await res.text();
  if (!res.ok) throw new Error(text || res.statusText);
  return text ? JSON.parse(text) : {};
}
