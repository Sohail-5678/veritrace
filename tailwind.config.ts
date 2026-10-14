import type { Config } from "tailwindcss";

/**
 * "Obsidian Glass & Bioluminescent Forensics" design tokens.
 * Colors are mirrored in globals.css as CSS variables so raw CSS and 3D
 * transforms can reference them too.
 */
const config: Config = {
  content: [
    "./src/app/**/*.{ts,tsx}",
    "./src/components/**/*.{ts,tsx}",
    "./src/lib/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        obsidian: {
          DEFAULT: "#06080D",
          800: "#0A0E16",
          700: "#0F1420",
          600: "#141B2B",
          500: "#1C2538",
        },
        // Forensic semantic accents
        clean: "#10B981", // entropy-locked fact / sanitized
        caution: "#F59E0B", // medium entropy / stylistic tell
        threat: "#F43F5E", // high watermark capacity / stego / injection
        analytic: "#06B6D4", // electric cyan analytical accent
        violetcore: "#8B5CF6",
      },
      fontFamily: {
        sans: ["var(--font-inter)", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "monospace"],
      },
      letterSpacing: {
        tightest: "-0.02em",
      },
      boxShadow: {
        glass:
          "0 24px 60px -12px rgba(0,0,0,0.65), inset 0 1px 0 0 rgba(255,255,255,0.12)",
        "glass-sm": "inset 0 1px 0 0 rgba(255,255,255,0.10)",
        glow: "0 0 40px -8px var(--tw-shadow-color)",
      },
      backdropBlur: {
        glass: "24px",
      },
      keyframes: {
        "aurora-drift": {
          "0%,100%": { transform: "translate3d(0,0,0) scale(1)" },
          "50%": { transform: "translate3d(2%, -3%, 0) scale(1.08)" },
        },
        "pulse-ring": {
          "0%": { opacity: "0.9", transform: "scale(0.9)" },
          "70%": { opacity: "0", transform: "scale(1.9)" },
          "100%": { opacity: "0" },
        },
        shimmer: {
          "100%": { transform: "translateX(100%)" },
        },
        "fade-up": {
          "0%": { opacity: "0", transform: "translateY(12px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        scan: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(400%)" },
        },
      },
      animation: {
        "aurora-drift": "aurora-drift 16s ease-in-out infinite",
        "pulse-ring": "pulse-ring 2.4s cubic-bezier(0.25,0.8,0.25,1) infinite",
        shimmer: "shimmer 2.5s infinite",
        "fade-up": "fade-up 0.5s cubic-bezier(0.22,1,0.36,1) both",
        scan: "scan 3.2s linear infinite",
      },
    },
  },
  plugins: [],
};

export default config;
