/** @type {import('tailwindcss').Config} */
export default {
  content: ["./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}"],
  theme: {
    extend: {
      colors: {
        "kao-required": "#1a7f37",
        "kao-conditional": "#9a6700",
        "kao-optional": "#0969da",
        "kao-deprecated": "#6e7781",
      },
    },
  },
  plugins: [],
};
