import { useEffect, useState } from "react";
import { getJson, shortDate, type Email } from "./api";
import { Band, Frame } from "./Chrome";

export function Outbox() {
  const [data, setData] = useState<{ resend: boolean; emails: Email[] } | null>(null);
  useEffect(() => {
    getJson<{ resend: boolean; emails: Email[] }>("/api/outbox").then(setData);
  }, []);
  return (
    <Frame>
      <Band crumb={<><a href="/">Home</a> / <span>Sent emails</span></>} title="Sent emails">
        {data && (
          <p className="muted">
            {data.resend ? "Emails are sent through Resend and also listed here." : "RESEND_API_KEY is not set, so emails are only listed here."}
          </p>
        )}
      </Band>
      <section className="section">
        <div className="wrap narrow">
          {data && data.emails.length === 0 && <p className="muted">No emails yet.</p>}
          <div className="rows">
            {data?.emails.map((e) => (
              <article key={e.at + e.to} className="card email">
                <div className="card-head">
                  <strong>{e.subject}</strong>
                  <span className={`pill pill-${e.delivery === "resend" ? "green" : e.delivery === "outbox-only" ? "amber" : "red"}`} title={e.delivery}>
                    {e.delivery === "resend" ? "Sent via Resend" : e.delivery === "outbox-only" ? "Outbox only" : "Resend failed"}
                  </span>
                </div>
                <p className="muted small">
                  To {e.to} · {shortDate(e.at)}
                </p>
                <p>{e.body}</p>
                <a className="btn btn-primary btn-sm" href={e.link}>
                  Open link
                </a>
              </article>
            ))}
          </div>
        </div>
      </section>
    </Frame>
  );
}
