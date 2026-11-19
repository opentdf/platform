import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
  },
  resolve: {
    alias: {
      "@spec": new URL("../../", import.meta.url).pathname,
      "@": new URL("./src", import.meta.url).pathname,
    },
  },
});
