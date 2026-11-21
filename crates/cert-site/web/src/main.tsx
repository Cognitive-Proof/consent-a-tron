import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { Home } from "./Home";
import { DemoPage } from "./DemoPage";
import "./styles.css";

// Two pages, chosen by path. cert-site serves this app at / and /demo.
const page = location.pathname === "/" ? <Home /> : <DemoPage />;

createRoot(document.getElementById("root")!).render(<StrictMode>{page}</StrictMode>);
