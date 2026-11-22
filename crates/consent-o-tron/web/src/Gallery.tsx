import { useEffect, useMemo, useRef, useState } from "react";
import { getTemplates, humanize, shortDate, shortLabel, type Template } from "./api";
import { DEMO, Frame } from "./Chrome";
import { go, useSession } from "./session";
import { Wizard } from "./Wizard";

type Sort = "az" | "za" | "newest";

const CATEGORY_BLURB: Record<string, string> = {
  Editorial: "News, documentary and editorial photography, where a person's image is part of the story.",
  Commercial: "Advertising and campaigns, where a person's name or likeness helps sell something.",
  Performance: "Film, games and recorded performance, including voice and movement, with replica limits.",
};

/** A paper-style preview of the agreement, tinted per category. */
export function Thumb({ t }: { t: Template }) {
  return (
    <div className={`thumb thumb-${t.category.toLowerCase()}`} aria-hidden>
      <div className="paper">
        <span className="paper-title">{t.title.toUpperCase()}</span>
        {Array.from({ length: 7 }, (_, i) => (
          <span key={i} className="paper-line" style={{ width: `${92 - ((i * 17) % 38)}%` }} />
        ))}
        <span className="seal">✓</span>
      </div>
    </div>
  );
}

function TemplateCard({ t, featured, onOpen }: { t: Template; featured?: boolean; onOpen: () => void }) {
  return (
    <article className="tcard" onClick={onOpen}>
      <Thumb t={t} />
      <div className="tcard-body">
        <div className="tcard-tags">
          {featured && <span className="tag tag-red">Featured</span>}
          <span className="tag">{t.category}</span>
        </div>
        <h3>{t.title}</h3>
        <p className="muted">{t.description}</p>
        <div className="chips">
          {t.public.map((f) => (
            <span key={f.name} className="chip">
              {shortLabel(f.label)}
            </span>
          ))}
        </div>
        <div className="tcard-foot">
          <span className="muted small">Updated {shortDate(t.updated)}</span>
          <button
            className="linklike strong"
            onClick={(e) => {
              e.stopPropagation();
              onOpen();
            }}
          >
            Use this agreement →
          </button>
        </div>
      </div>
    </article>
  );
}

export function Gallery({ wizardFor }: { wizardFor: string | null }) {
  const { user, requireLogin } = useSession();
  const [templates, setTemplates] = useState<Template[]>([]);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<string | null>(null);
  const [sort, setSort] = useState<Sort>("az");
  const results = useRef<HTMLDivElement>(null);

  useEffect(() => {
    getTemplates().then(setTemplates);
  }, []);

  // A deep link to /new/{template} needs a login first.
  useEffect(() => {
    if (wizardFor && user === null) requireLogin(() => {});
  }, [wizardFor, user, requireLogin]);

  const open = (t: Template) => {
    if (user) go(`/new/${t.id}`, { scroll: false });
    else requireLogin(() => go(`/new/${t.id}`, { scroll: false }));
  };

  const categories = useMemo(() => [...new Set(templates.map((t) => t.category))].sort(), [templates]);
  const filtering = query.trim() !== "" || category !== null;
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = templates.filter(
      (t) =>
        (!category || t.category === category) &&
        (!q ||
          [t.title, t.description, t.category, ...t.public.map((f) => f.label), ...t.public.flatMap((f) => f.options.map(humanize))]
            .join(" ")
            .toLowerCase()
            .includes(q)),
    );
    return list.sort((a, b) =>
      sort === "newest" ? b.updated.localeCompare(a.updated) : sort === "az" ? a.title.localeCompare(b.title) : b.title.localeCompare(a.title),
    );
  }, [templates, query, category, sort]);

  const wizardTemplate = wizardFor && user ? templates.find((t) => t.id === wizardFor) : undefined;

  return (
    <Frame>
      <section className="hero">
        <div className="wrap hero-inner">
          <div className="hero-copy">
            <div className="crumbs">
              <a href="/">Home</a> / <span>Agreement templates</span>
            </div>
            <h1>Consent agreement templates</h1>
            <p className="lead">
              Ask for consent to use someone's image, likeness or voice. You both sign, and the consent travels inside the file as a
              verifiable credential.
            </p>
            <form
              className="search"
              role="search"
              onSubmit={(e) => {
                e.preventDefault();
                results.current?.scrollIntoView({ behavior: "smooth" });
              }}
            >
              <span className="search-icon" aria-hidden>
                ⌕
              </span>
              <input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="What agreement are you looking for?"
                aria-label="Search agreements"
              />
              <button className="btn btn-primary">Search</button>
            </form>
            <p className="muted small hero-hint">
              Try “editorial”, “voice” or “AI training”.
            </p>
          </div>
          <img className="hero-robot" src="/robot.webp" alt="The Consent-O-Tron robot signing an agreement" width={420} height={420} />
        </div>
      </section>

      {!filtering && (
        <>
          <section className="section">
            <div className="wrap">
              <div className="section-head">
                <h2>Featured agreements</h2>
              </div>
              <div className="grid">
                {templates.map((t) => (
                  <TemplateCard key={t.id} t={t} featured onOpen={() => open(t)} />
                ))}
              </div>
            </div>
          </section>

          <section className="section section-sand">
            <div className="wrap">
              <div className="section-head">
                <h2>Popular categories</h2>
              </div>
              <div className="cats">
                {categories.map((c) => (
                  <button
                    key={c}
                    className="cat"
                    onClick={() => {
                      setCategory(c);
                      results.current?.scrollIntoView({ behavior: "smooth" });
                    }}
                  >
                    <span className={`cat-icon cat-${c.toLowerCase()}`} aria-hidden />
                    <strong>{c}</strong>
                    <span className="muted">{CATEGORY_BLURB[c] ?? ""}</span>
                  </button>
                ))}
              </div>
            </div>
          </section>
        </>
      )}

      <section className="section" ref={results} id="all">
        <div className="wrap">
          <div className="section-head">
            <h2>{filtering ? "Results" : "All agreements"}</h2>
            <label className="sort">
              Sort by
              <select value={sort} onChange={(e) => setSort(e.target.value as Sort)}>
                <option value="az">Name A to Z</option>
                <option value="za">Name Z to A</option>
                <option value="newest">Newest</option>
              </select>
            </label>
          </div>
          {filtering && (
            <div className="filters">
              {query.trim() && (
                <button className="filter" onClick={() => setQuery("")}>
                  “{query.trim()}” ×
                </button>
              )}
              {category && (
                <button className="filter" onClick={() => setCategory(null)}>
                  {category} ×
                </button>
              )}
              <span className="muted small">
                {shown.length} of {templates.length} agreements
              </span>
            </div>
          )}
          {shown.length ? (
            <div className="grid">
              {shown.map((t) => (
                <TemplateCard key={t.id} t={t} onOpen={() => open(t)} />
              ))}
            </div>
          ) : (
            <div className="empty">
              <img src="/mark.png" width={72} height={72} alt="" />
              <p>
                <strong>No agreements match “{query.trim()}”.</strong>
              </p>
              <p className="muted">There are only {templates.length} agreements in this demonstration.</p>
              <button
                className="btn btn-ghost"
                onClick={() => {
                  setQuery("");
                  setCategory(null);
                }}
              >
                Show all agreements
              </button>
            </div>
          )}
          <nav className="pager" aria-label="Pages">
            <button disabled aria-label="Previous page">
              ‹
            </button>
            <span className="current">1</span>
            <button disabled aria-label="Next page">
              ›
            </button>
          </nav>
        </div>
      </section>

      <section className="cta">
        <div className="wrap cta-inner">
          <img src="/robot.webp" alt="" width={200} height={200} />
          <div>
            <h2>Consent that travels inside the file</h2>
            <p>
              Anyone with the file can check who consented, to what, and whether that consent still stands. No account needed.
            </p>
            <div className="cta-actions">
              <a className="btn btn-primary" href="/verify">
                Verify a file
              </a>
              <a className="btn btn-ghost-light" href={DEMO}>
                Learn how it works
              </a>
            </div>
          </div>
        </div>
      </section>

      {wizardTemplate && <Wizard template={wizardTemplate} onClose={() => go("/", { scroll: false })} />}
    </Frame>
  );
}
