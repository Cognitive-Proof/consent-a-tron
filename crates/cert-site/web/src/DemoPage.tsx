import { Footer, Nav, TopBar } from "./Chrome";

export function DemoPage() {
  return (
    <>
      <TopBar />
      <Nav />
      <main className="demo-page">
        <div className="wrap demo-inner">
          <span className="eyebrow">NotSSL</span>
          <h1>This is a demonstration page. This content doesn't exist.</h1>
          <div className="hero-actions">
            <a className="btn btn-primary" href="/">
              Back to home
            </a>
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
