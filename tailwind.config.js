/** Tailwind v3 config for the standalone CLI (see Makefile `css` and the Dockerfile css stage). */
module.exports = {
  content: ["./app/templates/**/*.html", "./app/static/js/**/*.js"],
  theme: { extend: {} },
  plugins: [],
};
