import { DEMO, ENROLL, Footer, Nav, TopBar } from "./Chrome";
import { Logo } from "./Logo";

export function Home() {
  return (
    <>
      <TopBar />
      <Nav onHome />
      <main>
        <Hero />
        <Stats />
        <Certificates />
        <Assurance />
        <HowItWorks />
        <Features />
        <Resources />
        <Faq />
        <CtaBand />
      </main>
      <Footer />
    </>
  );
}

function Hero() {
  return (
    <section className="hero">
      <div className="wrap hero-inner">
        <div className="hero-copy">
          <span className="pill">New · Creator Assertions Working Group</span>
          <h1>We are supporting LOA2 CAWG Certificates</h1>
          <p className="lead">
            Prove who made it, and who agreed to it. A NotSSL CAWG certificate binds your verified identity to a key in your
            wallet, so your signature on a C2PA manifest can be checked by anyone.
          </p>
          <div className="hero-actions">
            <a className="btn btn-primary btn-lg" href="#certificates">
              Explore CAWG Certificates
            </a>
            <a className="btn btn-ghost btn-lg" href={DEMO}>
              Talk to an expert
            </a>
          </div>
          <ul className="hero-checks">
            <li>Issued in minutes</li>
            <li>Keys never leave your wallet</li>
            <li>From $5 / year</li>
          </ul>
        </div>
        <CertificateCard />
      </div>
    </section>
  );
}

/** A picture of the certificate the product issues. */
function CertificateCard() {
  return (
    <div className="cert-visual" aria-hidden="true">
      <div className="cert-card">
        <div className="cert-head">
          <span className="cert-brand">
            <Logo size={22} /> NotSSL
          </span>
          <span className="cert-level">LOA2</span>
        </div>
        <div className="cert-title">CAWG Identity Certificate</div>
        <dl className="cert-fields">
          <dt>Subject</dt>
          <dd>mailto:alex@example.com</dd>
          <dt>Key</dt>
          <dd>Ed25519 · did:key:z6Mk…q4Vt</dd>
          <dt>Issuer</dt>
          <dd>CAWG Test CA</dd>
          <dt>Valid</dt>
          <dd>Nov 21, 2026 → Nov 21, 2027</dd>
        </dl>
        <div className="cert-foot">
          <span className="cert-ok">● Verified identity</span>
          <span className="cert-seal">
            <Logo size={28} />
          </span>
        </div>
      </div>
      <div className="cert-chip chip-a">✓ Email verified</div>
      <div className="cert-chip chip-b">✓ ID checked</div>
    </div>
  );
}

function Stats() {
  const stats = [
    ["6 steps", "modeled on NIST LOA2"],
    ["Ed25519", "modern, fast signatures"],
    ["C2PA", "works with content credentials"],
    ["24/7", "demo support that doesn't exist"],
  ];
  return (
    <section className="stats">
      <div className="wrap stats-grid">
        {stats.map(([big, small]) => (
          <div key={big}>
            <strong>{big}</strong>
            <span>{small}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

type Product = {
  name: string;
  tag?: string;
  price: string;
  per: string;
  blurb: string;
  features: string[];
  href: string;
  cta: string;
  featured?: boolean;
};

const PRODUCTS: Product[] = [
  {
    name: "LOA2 CAWG Certificate",
    tag: "Most popular",
    price: "$5",
    per: "/ year",
    blurb: "For performers, creators and producers: sign your identity assertions, give consent, or ask for it.",
    features: [
      "Verified email in the certificate",
      "ID validated against records",
      "Code sent to your address of record",
      "Ed25519 key held in your wallet",
      "Listed in the TRQP trust registry",
    ],
    href: ENROLL,
    cta: "Get started",
    featured: true,
  },
  {
    name: "CAWG Organization",
    price: "$199",
    per: "/ year",
    blurb: "For studios, agencies and newsrooms that sign on behalf of a verified organization.",
    features: ["Organization validation", "Multiple signers per account", "Central key management", "Priority issuance"],
    href: DEMO,
    cta: "Contact sales",
  },
];

function Certificates() {
  return (
    <section id="certificates" className="section">
      <div className="wrap">
        <SectionHead
          eyebrow="CAWG Certificates"
          title="Pick the certificate that fits how you sign"
          text="Every NotSSL CAWG certificate is issued at Level of Assurance 2: your identity is checked before your key is certified."
        />
        <div className="products">
          {PRODUCTS.map((p) => (
            <article key={p.name} className={`product${p.featured ? " featured" : ""}`}>
              {p.tag && <span className="product-tag">{p.tag}</span>}
              <h3>{p.name}</h3>
              <p className="muted">{p.blurb}</p>
              <div className="price">
                <strong>{p.price}</strong>
                <span>{p.per}</span>
              </div>
              <ul className="checks">
                {p.features.map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
              <a className={`btn ${p.featured ? "btn-primary" : "btn-outline"}`} href={p.href}>
                {p.cta}
              </a>
            </article>
          ))}
        </div>
        <p className="center-note">
          Need document or code signing? <a href={DEMO}>Compare all certificates →</a>
        </p>
      </div>
    </section>
  );
}

function Assurance() {
  const levels = [
    { level: "LOA1", name: "Self-asserted", text: "Anyone can claim a name. Nothing is checked.", supported: false },
    { level: "LOA2", name: "Verified remotely", text: "ID validated against records, card address confirmed by the issuer, and a code sent to your address of record before issuance.", supported: true },
    { level: "LOA3", name: "In person", text: "Identity proofed in person or by a supervised remote session.", supported: false },
  ];
  return (
    <section id="assurance" className="section section-alt">
      <div className="wrap split">
        <div>
          <SectionHead
            eyebrow="Levels of assurance"
            title="Why LOA2 matters for consent"
            text="A consent credential is only as good as the identity behind it. LOA2 means a real person was checked before their key could sign on their behalf."
            left
          />
          <a className="btn btn-outline" href={DEMO}>
            Read the assurance guide
          </a>
        </div>
        <div className="levels">
          {levels.map((l) => (
            <div key={l.level} className={`level${l.supported ? " on" : ""}`}>
              <span className="level-badge">{l.level}</span>
              <div>
                <h4>
                  {l.name} {l.supported && <span className="supported">Supported</span>}
                </h4>
                <p>{l.text}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function HowItWorks() {
  const steps = [
    ["Enter your email", "Tell us who you are and whether you give or ask for consent."],
    ["Prove your mailbox", "Click the single-use link we send. It lasts 24 hours."],
    ["Pay", "Your card issuer confirms your billing address. Stripe test mode."],
    ["Match your ID to records", "Your name, date of birth and ID number are checked against records."],
    ["Confirm your address of record", "Enter the 6-digit code sent to the email on record."],
    ["Connect your wallet", "Your wallet sends its public key and receives the certificate."],
  ];
  return (
    <section id="how" className="section">
      <div className="wrap">
        <SectionHead eyebrow="How it works" title="From email to certificate in six steps" />
        <ol className="steps">
          {steps.map(([t, d], i) => (
            <li key={t}>
              <span className="step-num">{i + 1}</span>
              <h4>{t}</h4>
              <p>{d}</p>
            </li>
          ))}
        </ol>
        <div className="center-cta">
          <a className="btn btn-primary btn-lg" href={ENROLL}>
            Start now
          </a>
        </div>
      </div>
    </section>
  );
}

function Features() {
  const features = [
    ["🔑", "Your key stays yours", "Keys are created in your wallet and can't be exported. We only ever see the public key."],
    ["🧾", "Built for C2PA", "Sign CAWG identity assertions inside content credentials on images and video."],
    ["🏛️", "Trust registry", "Certificate holders are listed in a TRQP registry, so verifiers know who may issue consent."],
    ["↩️", "Withdraw any time", "Consent can be withdrawn through status lists, without touching the file."],
    ["⚡", "Fast issuance", "Most certificates are issued in under five minutes."],
    ["🛟", "Real humans*", "*Not real. This is a demonstration."],
  ];
  return (
    <section className="section section-dark">
      <div className="wrap">
        <SectionHead eyebrow="Why NotSSL" title="Everything you need to sign with confidence" dark />
        <div className="features">
          {features.map(([icon, t, d]) => (
            <div key={t} className="feature">
              <span className="feature-icon">{icon}</span>
              <h4>{t}</h4>
              <p>{d}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function Resources() {
  const items = [
    ["Guide", "What is a CAWG identity assertion?"],
    ["Article", "Consent credentials vs. model releases"],
    ["Webinar", "Signing content credentials at scale"],
  ];
  return (
    <section className="section">
      <div className="wrap">
        <SectionHead eyebrow="Resources" title="Learn more about content identity" />
        <div className="resources">
          {items.map(([kind, title]) => (
            <a key={title} className="resource" href={DEMO}>
              <span className="resource-kind">{kind}</span>
              <h4>{title}</h4>
              <span className="resource-more">Read more →</span>
            </a>
          ))}
        </div>
      </div>
    </section>
  );
}

function Faq() {
  const faqs = [
    ["What is a CAWG certificate?", "An X.509 certificate that ties your verified email to an Ed25519 key. You use it to sign CAWG identity assertions in C2PA manifests."],
    ["What does LOA2 mean?", "NIST Level of Assurance 2 (IAL2 today): your ID is validated against records, and a one-time code is sent to your address of record from those records before the certificate is issued."],
    ["Where do the records come from?", "A real CA checks your ID with its issuer and credit bureaus. This demo uses a mock records bureau where you create a made-up record first, so nobody pays for verification."],
    ["Do you keep my ID photos?", "No. In this demonstration the images are read and discarded immediately. They are never stored, logged, or checked."],
    ["Is this a real certificate authority?", "No. NotSSL is a demonstration. Certificates come from the CAWG test CA and are only trusted by the demo sites."],
    ["Can I use a card?", "Payments run in Stripe test mode. Use 4242 4242 4242 4242 with any future date and any CVC."],
  ];
  return (
    <section id="faq" className="section section-alt">
      <div className="wrap faq-wrap">
        <SectionHead eyebrow="FAQ" title="Questions, answered" />
        <div className="faq">
          {faqs.map(([q, a]) => (
            <details key={q}>
              <summary>{q}</summary>
              <p>{a}</p>
            </details>
          ))}
        </div>
      </div>
    </section>
  );
}

function CtaBand() {
  return (
    <section className="cta-band">
      <div className="wrap cta-inner">
        <div>
          <h2>Ready to sign with proof?</h2>
          <p>Get your LOA2 CAWG certificate in about five minutes.</p>
        </div>
        <div className="hero-actions">
          <a className="btn btn-light btn-lg" href={ENROLL}>
            Get certified
          </a>
          <a className="btn btn-ghost-light btn-lg" href={DEMO}>
            Contact sales
          </a>
        </div>
      </div>
    </section>
  );
}

function SectionHead(props: { eyebrow: string; title: string; text?: string; left?: boolean; dark?: boolean }) {
  return (
    <div className={`section-head${props.left ? " left" : ""}${props.dark ? " dark" : ""}`}>
      <span className="eyebrow">{props.eyebrow}</span>
      <h2>{props.title}</h2>
      {props.text && <p>{props.text}</p>}
    </div>
  );
}
