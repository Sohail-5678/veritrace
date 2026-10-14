import type { NextConfig } from "next";

/**
 * Content-Security-Policy for a zero-trust forensics tool.
 *
 * Notes on the directives:
 * - `script-src` keeps 'unsafe-inline' because Next.js injects a small inline
 *   bootstrap/hydration script. A nonce-based upgrade is documented in the
 *   README for teams that want to drop 'unsafe-inline'. 'unsafe-eval' is only
 *   needed by the dev HMR runtime, so it is added conditionally below.
 * - `style-src` needs 'unsafe-inline' because Framer Motion writes inline
 *   `style` attributes for animated transforms.
 * - Fonts are self-hosted via `next/font`, so no external font origins are
 *   required.
 * - `connect-src` allows api.groq.com ONLY so the optional BYOK rewrite can be
 *   called from the browser if a user pastes their own key. No key ships with
 *   the app.
 */
const isDev = process.env.NODE_ENV !== "production";

const csp = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ""}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src 'self' https://api.groq.com",
  "worker-src 'self' blob:",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "upgrade-insecure-requests",
]
  .join("; ")
  .trim();

const securityHeaders = [
  { key: "Content-Security-Policy", value: csp },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "X-DNS-Prefetch-Control", value: "off" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  },
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
];

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // The forensic engines are pure TS and type-checked; lint is skipped during
  // build only to keep `npm run build` frictionless on fresh clones.
  eslint: { ignoreDuringBuilds: true },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: securityHeaders,
      },
    ];
  },
};

export default nextConfig;
