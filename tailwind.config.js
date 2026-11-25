/** Tailwind v3 config for the standalone CLI (see Makefile `css` and the Dockerfile css stage).
 *  Colours are CSS variables (assets/tools.css) so light/dark and the embed accent override work without a rebuild. */
module.exports = {
  content: ["./app/templates/**/*.html", "./app/static/js/**/*.js"],
  theme: {
    extend: {
      colors: {
        bg: "var(--bg)", surface: "var(--surface)", surface2: "var(--surface2)", line: "var(--line)",
        ink: "var(--ink)", mute: "var(--mute)", accent: "var(--accent)",
        ok: "var(--ok)", warn: "var(--warn)", bad: "var(--bad)",
      },
    },
  },
  plugins: [],
};
