/**
 * Security Guardrail #5 — Stateless-ish Rate Limiting & Client Challenge
 * -----------------------------------------------------------------------------
 * A $0 abuse brake: an in-memory token bucket keyed by client fingerprint
 * (IP + UA hash), plus an optional HMAC-signed proof-of-work-style challenge.
 *
 * Limitation (documented): serverless instances each hold their own memory, so
 * this is a best-effort brake, not a global quota. It needs no Redis/Upstash,
 * which keeps the project free. Swap the Map for Upstash to make it global.
 */

export const DEFAULT_RATE = Number(process.env.RATE_LIMIT_PER_MINUTE ?? 15);
const WINDOW_MS = 60_000;

interface Bucket {
  tokens: number;
  updated: number;
}

const buckets = new Map<string, Bucket>();

// prevent unbounded growth of the map
let lastSweep = Date.now();
function sweep(now: number) {
  if (now - lastSweep < WINDOW_MS) return;
  lastSweep = now;
  for (const [k, b] of buckets) {
    if (now - b.updated > WINDOW_MS * 5) buckets.delete(k);
  }
}

export interface RateResult {
  allowed: boolean;
  remaining: number;
  limit: number;
  retryAfterMs: number;
}

/** Token-bucket check. One call consumes one token. */
export function checkRate(clientId: string, limit = DEFAULT_RATE): RateResult {
  const now = Date.now();
  sweep(now);
  const refillPerMs = limit / WINDOW_MS;
  let b = buckets.get(clientId);
  if (!b) {
    b = { tokens: limit, updated: now };
    buckets.set(clientId, b);
  }
  // refill
  const elapsed = now - b.updated;
  b.tokens = Math.min(limit, b.tokens + elapsed * refillPerMs);
  b.updated = now;

  if (b.tokens >= 1) {
    b.tokens -= 1;
    return {
      allowed: true,
      remaining: Math.floor(b.tokens),
      limit,
      retryAfterMs: 0,
    };
  }
  const deficit = 1 - b.tokens;
  return {
    allowed: false,
    remaining: 0,
    limit,
    retryAfterMs: Math.ceil(deficit / refillPerMs),
  };
}

/** Derive a stable-ish client id from request headers. */
export function getClientId(headers: Headers): string {
  const xff = headers.get("x-forwarded-for");
  const ip =
    (xff ? xff.split(",")[0].trim() : "") ||
    headers.get("x-real-ip") ||
    "anon";
  const ua = headers.get("user-agent") ?? "";
  // tiny non-crypto fingerprint hash of UA to separate obvious bots
  let h = 2166136261;
  for (let i = 0; i < ua.length; i++) {
    h ^= ua.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return `${ip}:${(h >>> 0).toString(36)}`;
}

/* --------------------------- HMAC challenge ------------------------------ */

function getSecret(): string {
  if (!process.env.RATE_LIMIT_SECRET) {
    // ephemeral per-boot secret (fine for a single instance)
    (process.env as Record<string, string>).RATE_LIMIT_SECRET =
      Math.random().toString(36).slice(2) + Date.now().toString(36);
  }
  return process.env.RATE_LIMIT_SECRET!;
}

async function hmac(message: string, secret: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Issue a short-lived signed challenge token (binds a client for ~2 min). */
export async function createClientChallenge(clientId: string): Promise<string> {
  const payload = `${clientId}.${Date.now()}`;
  const sig = await hmac(payload, getSecret());
  return `${btoa(payload)}.${sig}`;
}

/** Verify a challenge token's signature and freshness. */
export async function verifyClientChallenge(
  token: string,
  maxAgeMs = 120_000,
): Promise<boolean> {
  try {
    const [b64, sig] = token.split(".");
    if (!b64 || !sig) return false;
    const payload = atob(b64);
    const expected = await hmac(payload, getSecret());
    if (expected !== sig) return false;
    const ts = Number(payload.split(".").pop());
    return Number.isFinite(ts) && Date.now() - ts < maxAgeMs;
  } catch {
    return false;
  }
}
