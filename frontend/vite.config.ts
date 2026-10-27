/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In development the dashboard runs on :5173 and forwards /api to the Python API on :8000.
// `npm run build` writes static files to dist/, which the Python API then serves itself.
export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: { "/api": "http://127.0.0.1:8000" },
  },
  // assetsInlineLimit 0: fonts are served as files, because the CSP does not allow data: fonts.
  build: { outDir: "dist", sourcemap: false, chunkSizeWarningLimit: 900, assetsInlineLimit: 0 },
  test: {
    environment: "jsdom",
    setupFiles: ["src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
