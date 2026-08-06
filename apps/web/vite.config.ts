import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const page = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      input: {
        main: page("index.html"),
        "guide-ssh": page("guides/send-ssh-key-securely.html"),
        "guide-password": page("guides/share-password-one-time-link.html"),
        "guide-api": page("guides/send-api-key-securely.html"),
        "guide-cli": page("guides/cli.html"),
        compare: page("compare/secret-sharing-tools.html"),
        blog: page("blog.html"),
        "blog-park-first": page("blog/park-first-secret-sharing.html"),
      },
    },
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8787",
      "/auth": "http://127.0.0.1:8787",
      "/ws": { target: "ws://127.0.0.1:8787", ws: true },
    },
  },
});
