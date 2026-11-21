import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// cert-site serves the build (dist/) at / and /demo. In `npm run dev`, the
// enrollment flow and other server routes are proxied to cert-site on 4001.
const certSite = "http://localhost:4001";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/enroll": certSite,
      "/verify": certSite,
      "/outbox": certSite,
      "/static": certSite,
      "/trqp": certSite,
    },
  },
});
