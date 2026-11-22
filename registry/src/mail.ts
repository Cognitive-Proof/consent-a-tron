import type { Collection } from "mongodb";

export interface Email {
  site: string;
  at: string;
  to: string;
  subject: string;
  body: string;
  link: string;
  delivery: string;
}

/**
 * Sends through Resend when RESEND_API_KEY is set, and keeps every email in
 * the shared `outbox` collection (shown at /outbox), as the Rust sites do.
 */
export class Mailer {
  private readonly key = process.env.RESEND_API_KEY?.trim() || null;
  private readonly from = process.env.EMAIL_FROM?.trim() || "Consent Demo <onboarding@resend.dev>";

  constructor(private readonly outbox: Collection<Email>) {}

  get usesResend(): boolean {
    return this.key !== null;
  }

  async send(to: string, subject: string, body: string, link: string): Promise<void> {
    let delivery = "outbox-only";
    if (this.key) {
      try {
        const res = await fetch("https://api.resend.com/emails", {
          method: "POST",
          headers: { Authorization: `Bearer ${this.key}`, "Content-Type": "application/json" },
          body: JSON.stringify({ from: this.from, to: [to], subject, text: `${body}\n\n${link}\n` }),
        });
        delivery = res.ok ? "resend" : `resend-failed: ${res.status} ${await res.text()}`;
      } catch (err) {
        delivery = `resend-failed: ${(err as Error).message}`;
      }
      if (delivery !== "resend") console.error(`${delivery} (email kept in outbox)`);
    }
    await this.outbox.insertOne({ site: "registry", at: new Date().toISOString().replace(/\.\d+Z$/, "Z"), to, subject, body, link, delivery });
  }

  async recent(): Promise<Email[]> {
    const emails = await this.outbox.find({ site: "registry" }).toArray();
    return emails.sort((a, b) => b.at.localeCompare(a.at)).slice(0, 50);
  }
}
