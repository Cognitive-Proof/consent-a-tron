import { Logo } from "./Logo";

/** Every link without real content goes here. */
export const DEMO = "/demo";
/** The real enrollment flow, served by cert-site. */
export const ENROLL = "/enroll";

export function TopBar() {
  return (
    <div className="topbar">
      <div className="wrap topbar-inner">
        <span>
          <strong>Demonstration site.</strong> NotSSL is not a real certificate authority; certificates come from the CAWG test CA.
        </span>
        <nav>
          <a href={DEMO}>Support</a>
          <a href={DEMO}>Contact sales</a>
          <a href={DEMO}>Log in</a>
        </nav>
      </div>
    </div>
  );
}

export function Nav({ onHome = false }: { onHome?: boolean }) {
  // On the home page, section links scroll; elsewhere they lead back to it.
  const section = (id: string) => (onHome ? `#${id}` : `/#${id}`);
  return (
    <header className="nav">
      <div className="wrap nav-inner">
        <a className="brand" href="/">
          <Logo size={34} />
          <span>NotSSL</span>
        </a>
        <nav className="nav-links">
          <a href={section("certificates")}>Certificates</a>
          <a href={section("assurance")}>Assurance levels</a>
          <a href={section("how")}>How it works</a>
          <a href={section("faq")}>FAQ</a>
          <a href={DEMO}>Resources</a>
        </nav>
        <a className="btn btn-primary btn-sm" href={ENROLL}>
          Get certified
        </a>
      </div>
    </header>
  );
}

const FOOTER: [string, string[]][] = [
  ["Certificates", ["LOA2 CAWG Individual", "CAWG Organization", "Document Signing", "Code Signing", "Compare certificates"]],
  ["Solutions", ["Newsrooms", "Studios & agencies", "Talent & performers", "Platforms", "Enterprise PKI"]],
  ["Resources", ["What is CAWG?", "Levels of assurance", "C2PA explained", "Developer docs", "Status"]],
  ["Company", ["About NotSSL", "Careers", "Press", "Legal & policies", "Contact"]],
];

export function Footer() {
  return (
    <footer className="footer">
      <div className="wrap">
        <div className="footer-grid">
          <div className="footer-brand">
            <a className="brand brand-light" href="/">
              <Logo size={30} />
              <span>NotSSL</span>
            </a>
            <p>Identity certificates for the people behind the content.</p>
            <form
              className="newsletter"
              onSubmit={(e) => {
                e.preventDefault();
                location.href = DEMO;
              }}
            >
              <label htmlFor="newsletter-email">Get product updates</label>
              <div>
                <input id="newsletter-email" type="email" placeholder="you@example.com" required />
                <button className="btn btn-primary btn-sm">Subscribe</button>
              </div>
            </form>
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
          <span>© {new Date().getFullYear()} NotSSL. Demonstration only. No real certificates are sold.</span>
          <nav>
            <a href={DEMO}>Privacy</a>
            <a href={DEMO}>Terms</a>
            <a href={DEMO}>CPS</a>
            <a href="/records">Records bureau</a>
            <a href="/outbox">Sent emails</a>
          </nav>
        </div>
      </div>
    </footer>
  );
}
