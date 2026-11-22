import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// consent-o-tron serves the build (dist/) for every page route. In
// `npm run dev`, the API, files and wallet client are proxied to it on 4003.
const consentSite = "http://localhost:4003";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": consentSite,
      "/status": consentSite,
      "/static": consentSite,
      "^/a/[^/]+/(asset|signed\\.jpg)$": consentSite,
    },
  },
});
