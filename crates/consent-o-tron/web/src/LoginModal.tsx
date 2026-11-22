import { useState } from "react";
import type { User } from "./api";
import { Modal } from "./Modal";
import { useSession } from "./session";
import { logIn } from "./wallet";

export function LoginModal({ onClose, onLoggedIn }: { onClose: () => void; onLoggedIn: (u: User) => void }) {
  const { certSite } = useSession();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <Modal title="Log in to Consent-O-Tron" onClose={onClose}>
      <div className="login">
        <img src="/mark.png" width={88} height={88} alt="" />
        <p>
          Log in with your <strong>Consent Wallet</strong>. Your wallet identity needs a certificate from{" "}
          <a href={certSite}>NotSSL</a>. The email on that certificate is who you are here.
        </p>
        <button
          className="btn btn-primary btn-block"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            setError("");
            try {
              onLoggedIn(await logIn());
            } catch (e) {
              setError((e as Error).message);
              setBusy(false);
            }
          }}
        >
          {busy ? "Choose an identity in your wallet…" : "Log in with wallet"}
        </button>
        {error && <p className="error">{error}</p>}
        <p className="fine">
          No certificate yet? <a href={certSite}>Get certified on NotSSL</a>, then come back.
        </p>
      </div>
    </Modal>
  );
}
