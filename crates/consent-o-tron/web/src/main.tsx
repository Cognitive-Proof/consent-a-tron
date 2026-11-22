import { StrictMode, useCallback, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { getJson, type User } from "./api";
import { Session } from "./session";
import { Gallery } from "./Gallery";
import { Agreements } from "./Agreements";
import { AgreementPage } from "./AgreementPage";
import { VerifyAgreement, VerifyUpload } from "./Verify";
import { Outbox } from "./Outbox";
import { DemoPage } from "./DemoPage";
import { LoginModal } from "./LoginModal";
import "./styles.css";

function usePath() {
  const [path, setPath] = useState(location.pathname);
  useEffect(() => {
    const onPop = () => setPath(location.pathname);
    addEventListener("popstate", onPop);
    return () => removeEventListener("popstate", onPop);
  }, []);
  return path;
}

function App() {
  const path = usePath();
  const [user, setUser] = useState<User | null | undefined>(undefined);
  // Set while the login dialog is open; called once the person has logged in.
  const [loginThen, setLoginThen] = useState<null | ((u: User) => void)>(null);

  const [certSite, setCertSite] = useState("http://localhost:4001");
  useEffect(() => {
    getJson<User | null>("/api/me").then(setUser, () => setUser(null));
    getJson<{ certSite: string }>("/api/config").then((c) => setCertSite(c.certSite), () => {});
  }, []);

  const requireLogin = useCallback((then: (u: User) => void = () => {}) => {
    setLoginThen(() => then);
  }, []);

  const m = (re: RegExp) => path.match(re);
  let page;
  let match: RegExpMatchArray | null;
  if (path === "/" || (match = m(/^\/new\/([^/]+)$/))) {
    page = <Gallery wizardFor={m(/^\/new\/([^/]+)$/)?.[1] ?? null} />;
  } else if (path === "/agreements") {
    page = <Agreements />;
  } else if ((match = m(/^\/a\/([^/]+)\/verify$/))) {
    page = <VerifyAgreement id={match[1]} />;
  } else if ((match = m(/^\/a\/([^/]+)$/))) {
    page = <AgreementPage id={match[1]} />;
  } else if (path === "/verify") {
    page = <VerifyUpload />;
  } else if (path === "/outbox") {
    page = <Outbox />;
  } else {
    page = <DemoPage />;
  }

  return (
    <Session.Provider value={{ user, setUser, requireLogin, certSite }}>
      {page}
      {loginThen && (
        <LoginModal
          onClose={() => setLoginThen(null)}
          onLoggedIn={(u) => {
            setUser(u);
            setLoginThen(null);
            loginThen(u);
          }}
        />
      )}
    </Session.Provider>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
