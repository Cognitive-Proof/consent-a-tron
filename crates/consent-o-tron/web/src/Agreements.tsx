import { useEffect, useState } from "react";
import { ApiError, getJson, shortDate, type AgreementSummary } from "./api";
import { Band, Frame } from "./Chrome";
import { useSession } from "./session";

export function stageLabel(a: { stage: AgreementSummary["stage"]; revoked: boolean }): [string, string] {
  if (a.revoked) return ["red", "Consent withdrawn"];
  switch (a.stage) {
    case "awaiting_producer":
      return ["amber", "Waiting for producer signature"];
    case "awaiting_cosigner":
      return ["amber", "Waiting for consent"];
    case "authoring":
      return ["amber", "Writing file"];
    case "signed":
      return ["green", "Signed"];
    case "failed":
      return ["red", "Failed"];
  }
}

export function StagePill(props: { stage: AgreementSummary["stage"]; revoked: boolean }) {
  const [tone, text] = stageLabel(props);
  return <span className={`pill pill-${tone}`}>{text}</span>;
}

/** Whose move it is, from the viewer's side. */
function group(a: AgreementSummary): number {
  if (a.revoked || a.stage === "failed") return 3;
  if (a.stage === "signed") return 2;
  const mine = (a.stage === "awaiting_producer" && a.role === "producer") || (a.stage === "awaiting_cosigner" && a.role === "cosigner");
  return mine ? 0 : 1;
}

const GROUPS = ["Needs your action", "Waiting on others", "Completed", "Withdrawn or failed"];

export function Agreements() {
  const { user, requireLogin } = useSession();
  const [items, setItems] = useState<AgreementSummary[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!user) return;
    getJson<AgreementSummary[]>("/api/agreements").then(setItems, (e: ApiError) => setError(e.message));
  }, [user]);

  return (
    <Frame>
      <Band crumb={<><a href="/">Home</a> / <span>My agreements</span></>} title="My agreements">
        {user && <p className="muted">Logged in as {user.email}</p>}
      </Band>
      <section className="section">
        <div className="wrap">
          {user === null && (
            <div className="empty">
              <img src="/mark.png" width={72} height={72} alt="" />
              <p>
                <strong>Log in to see your agreements.</strong>
              </p>
              <button className="btn btn-primary" onClick={() => requireLogin()}>
                Log in with wallet
              </button>
            </div>
          )}
          {error && <p className="error">{error}</p>}
          {user && items && items.length === 0 && (
            <div className="empty">
              <img src="/mark.png" width={72} height={72} alt="" />
              <p>
                <strong>No agreements yet.</strong>
              </p>
              <a className="btn btn-primary" href="/">
                Choose an agreement template
              </a>
            </div>
          )}
          {user &&
            items &&
            GROUPS.map((title, g) => {
              const list = items.filter((a) => group(a) === g);
              if (!list.length) return null;
              return (
                <div key={title} className="group">
                  <h2>
                    {title} <span className="count">{list.length}</span>
                  </h2>
                  <div className="rows">
                    {list.map((a) => (
                      <a key={a.id} className="row-card" href={`/a/${a.id}`}>
                        <img src={`/a/${a.id}/asset`} alt="" loading="lazy" />
                        <div className="row-main">
                          <strong>{a.title}</strong>
                          <span className="muted small">
                            {a.assetName} · {a.role === "producer" ? `with ${a.counterparty}` : `from ${a.counterparty}`} ·{" "}
                            {shortDate(a.createdAt)}
                          </span>
                        </div>
                        <StagePill stage={a.stage} revoked={a.revoked} />
                      </a>
                    ))}
                  </div>
                </div>
              );
            })}
          {user && (
            <p className="after-list">
              <a className="btn btn-ghost" href="/">
                New agreement
              </a>
            </p>
          )}
        </div>
      </section>
    </Frame>
  );
}
