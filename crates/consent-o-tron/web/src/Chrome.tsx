import type { ReactNode } from "react";
import { postJson } from "./api";
import { useSession } from "./session";

/** Every link without real content goes here. */
export const DEMO = "/demo";

export function Mark({ size = 40 }: { size?: number }) {
  return <img className="mark" src="/mark.png" width={size} height={size} alt="" />;
}

export function TopBar() {
  const { user, setUser, requireLogin } = useSession();
  return (
    <div className="topbar">
      <div className="wrap topbar-inner">
        <span>
          <strong>Demonstration site.</strong> Consent-O-Tron is a CAWG consent test, not a real service.
        </span>
        <nav>
          <a href={DEMO}>Support</a>
          <a href={DEMO}>Contact sales</a>
          {user ? (
            <button
              className="linklike"
              onClick={async () => {
                await postJson("/api/logout", {});
                setUser(null);
              }}
            >
              Log out
            </button>
          ) : (
            <button className="linklike" onClick={() => requireLogin()}>
              Log in
            </button>
          )}
        </nav>
      </div>
    </div>
  );
}

export function Header() {
  const { user } = useSession();
  return (
    <header className="header">
      <div className="wrap header-inner">
        <a className="brand" href="/">
          <Mark size={44} />
          <span>Consent-O-Tron</span>
        </a>
        <nav className="nav-links">
          <a href={DEMO}>Products</a>
          <a href={DEMO}>Solutions</a>
          <a href="/">Templates</a>
          <a href={DEMO}>Resources</a>
          <a href={DEMO}>Pricing</a>
        </nav>
        <div className="header-actions">
          <a className="nav-plain" href="/verify">
            Verify a file
          </a>
          {user ? (
            <a className="btn btn-primary btn-sm" href="/agreements" title={user.email}>
              My agreements
            </a>
          ) : (
            <a className="btn btn-primary btn-sm" href={DEMO}>
              Try free
            </a>
          )}
        </div>
      </div>
    </header>
  );
}

const FOOTER: [string, string[]][] = [
  ["Product", ["Consent agreements", "Signed files", "Withdrawal", "Integrations", "API"]],
  ["Solutions", ["Newsrooms", "Studios", "Agencies", "Talent & performers", "Platforms"]],
  ["Resources", ["What is CAWG?", "C2PA explained", "Template library", "Developer docs", "Status"]],
  ["Company", ["About", "Careers", "Press", "Trust center", "Contact"]],
];

export function Footer() {
  const { certSite } = useSession();
  return (
    <footer className="footer">
      <div className="wrap">
        <div className="footer-grid">
          <div className="footer-brand">
            <a className="brand brand-light" href="/">
              <Mark size={40} />
              <span>Consent-O-Tron</span>
            </a>
            <p>Consent that travels inside the file.</p>
            <div className="social">
              {["in", "yt", "x", "ig"].map((s) => (
                <a key={s} href={DEMO} aria-label={s}>
                  {s}
                </a>
              ))}
            </div>
          </div>
          {FOOTER.map(([title, links]) => (
            <div key={title}>
              <h4>{title}</h4>
              <ul>
                {links.map((l) => (
                  <li key={l}>
                    <a href={DEMO}>{l}</a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="footer-bottom">
          <span>© {new Date().getFullYear()} Consent-O-Tron. Demonstration only.</span>
          <nav>
            <a href={DEMO}>Privacy</a>
            <a href={DEMO}>Terms of use</a>
            <a href={DEMO}>Cookie settings</a>
            <a href={certSite}>NotSSL</a>
            <a href="/outbox">Sent emails</a>
          </nav>
        </div>
      </div>
    </footer>
  );
}

/** Top bar, header, page body and footer. */
export function Frame({ children }: { children: ReactNode }) {
  return (
    <>
      <TopBar />
      <Header />
      <main>{children}</main>
      <Footer />
    </>
  );
}

/** The sand band at the top of inner pages. */
export function Band({ crumb, title, children }: { crumb: ReactNode; title: ReactNode; children?: ReactNode }) {
  return (
    <section className="band">
      <div className="wrap">
        <div className="crumbs">{crumb}</div>
        <h1>{title}</h1>
        {children}
      </div>
    </section>
  );
}
