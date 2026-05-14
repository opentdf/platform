import { defineConfig } from "astro/config";
import preact from "@astrojs/preact";
import tailwind from "@astrojs/tailwind";

// https://astro.build/config
export default defineConfig({
  output: "static",
  trailingSlash: "ignore",
  integrations: [preact(), tailwind()],
  vite: {
    resolve: {
      alias: {
        "@spec": new URL("../../", import.meta.url).pathname,
      },
    },
  },
});
