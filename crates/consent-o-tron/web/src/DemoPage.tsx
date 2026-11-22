import { Frame } from "./Chrome";

export function DemoPage() {
  return (
    <Frame>
      <section className="demo-page">
        <div className="wrap demo-inner">
          <img src="/robot.webp" alt="" width={220} height={220} />
          <h1>This is a demonstration page.</h1>
          <p className="muted">This content doesn't exist.</p>
          <a className="btn btn-primary" href="/">
            Back to home
          </a>
        </div>
      </section>
    </Frame>
  );
}
