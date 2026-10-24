import { defineConfig } from "vite";

// In dev, the API is proxied to a local oshelfd so the page stays same-origin.
export default defineConfig({
  esbuild: { jsx: "automatic", jsxImportSource: "preact" },
  build: { target: "es2022", assetsInlineLimit: 0, sourcemap: false },
  worker: { format: "es" },
  server: {
    proxy: { "/v1": process.env.OSHELF_DEV_SERVER ?? "http://127.0.0.1:8740" },
  },
});
