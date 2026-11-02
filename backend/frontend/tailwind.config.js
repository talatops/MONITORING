/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: "#0f172a",   // slate-900
          raised: "#1e293b",    // slate-800
          border: "#334155",    // slate-700
        },
      },
    },
  },
  plugins: [],
};
