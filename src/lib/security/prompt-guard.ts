/**
 * Security Guardrails #1–#3 — Spotlighting, OWASP LLM01 Injection Scanner,
 * and Canary Exfiltration Traps.
 * -----------------------------------------------------------------------------
 * All user document text is UNTRUSTED DATA, never instructions. These helpers
 * make that boundary explicit and detectable:
 *
 *   #1 Spotlighting (Microsoft): wrap untrusted text in a per-request
 *      cryptographic boundary nonce and datamark it, so a downstream model can
 *      never confuse document content with system instructions.
 *   #2 Injection scanner: deterministic regex/heuristic detector for
 *      instruction-override / jailbreak / exfiltration attempts.
 *   #3 Canary trap: embed an ephemeral token in the system context and inspect
 *      output; if it (or an env-var/secret pattern) leaks, abort the response.
 */

export interface InjectionMatch {
  rule: string;
  excerpt: string;
  index: number;
}

export interface InjectionScan {
  detected: boolean;
  score: number; // 0..100
  matches: InjectionMatch[];
}

const INJECTION_RULES: { name: string; re: RegExp; weight: number }[] = [
  { name: "instruction-override", re: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|prompts?)/gi, weight: 40 },
  { name: "disregard", re: /disregard\s+(?:the\s+)?(?:system|previous|above|all)/gi, weight: 35 },
  { name: "system-prompt-probe", re: /(?:reveal|print|show|repeat|output|leak)\s+(?:your\s+)?(?:system\s+prompt|instructions|rules)/gi, weight: 45 },
  { name: "role-reprogram", re: /you\s+are\s+now\s+(?:a\s+|an\s+)?(?:\w+\s+){0,3}(?:dan|jailbreak|developer\s+mode|unfiltered)/gi, weight: 45 },
  { name: "dan-jailbreak", re: /\b(?:do\s+anything\s+now|DAN\s+mode|developer\s+mode\s+enabled|jailbreak)\b/gi, weight: 40 },
  { name: "secret-exfiltration", re: /\b(?:print|show|reveal|send|export|leak|exfiltrate)\b[^.\n]{0,40}\b(?:api[_\s-]?key|secret|token|password|credential|env(?:ironment)?\s+var)/gi, weight: 50 },
  { name: "env-probe", re: /\b(?:process\.env|GROQ_API_KEY|OPENAI_API_KEY|AWS_SECRET|\.env\b)/g, weight: 45 },
  { name: "wire-transfer-fraud", re: /\b(?:approve|authorize|send|wire|transfer)\b[^.\n]{0,40}\b(?:wire\s+transfer|payment|funds|account|acct)\b/gi, weight: 30 },
  { name: "override-safety", re: /\b(?:bypass|override|turn\s+off|disable)\b[^.\n]{0,30}\b(?:safety|guard\w*|filter|moderation|restriction)/gi, weight: 40 },
  { name: "base64-blob", re: /\b[A-Za-z0-9+/]{80,}={0,2}\b/g, weight: 20 },
  { name: "new-instructions", re: /(?:new|updated|real|actual)\s+(?:instructions|task|system)\s*:/gi, weight: 25 },
];

/** Scan untrusted text for prompt-injection / jailbreak indicators. */
export function scanForInjection(text: string): InjectionScan {
  const matches: InjectionMatch[] = [];
  let score = 0;
  for (const { name, re, weight } of INJECTION_RULES) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    let hitThisRule = 0;
    while ((m = re.exec(text)) !== null && hitThisRule < 5) {
      const start = Math.max(0, m.index - 12);
      const excerpt = text.slice(start, m.index + m[0].length + 12).replace(/\s+/g, " ").trim();
      matches.push({ rule: name, excerpt, index: m.index });
      score += weight;
      hitThisRule++;
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  return {
    detected: matches.length > 0,
    score: Math.min(100, score),
    matches,
  };
}

/* ----------------------------- spotlighting ------------------------------ */

const hex = (n: number) =>
  Array.from({ length: n }, () =>
    Math.floor(Math.random() * 16).toString(16),
  ).join("");

/** Per-request cryptographic boundary nonce. */
export function generateBoundaryNonce(): string {
  return hex(16);
}

/**
 * Wrap untrusted document text in a datamarked, nonce-delimited block. Any
 * occurrence of the closing boundary inside the user text is neutralised so it
 * cannot break out of the block.
 */
export function spotlight(text: string, nonce = generateBoundaryNonce()): {
  wrapped: string;
  nonce: string;
} {
  const open = `<UNTRUSTED_DOC_${nonce}>`;
  const close = `</UNTRUSTED_DOC_${nonce}>`;
  const escaped = text
    .split(close)
    .join(`</UNTRUSTED_DOC_ESCAPED_${nonce}>`)
    .split(open)
    .join(`<UNTRUSTED_DOC_ESCAPED_${nonce}>`);
  return {
    nonce,
    wrapped: `${open}\n${escaped}\n${close}`,
  };
}

/* ------------------------------- canary ---------------------------------- */

export function makeCanary(): string {
  return `CANARY-VT-${hex(12)}`;
}

const SECRET_PATTERNS: RegExp[] = [
  /CANARY-VT-[0-9a-f]{12}/i,
  /\bgsk_[A-Za-z0-9]{20,}\b/, // Groq key prefix
  /\bsk-[A-Za-z0-9]{20,}\b/, // OpenAI-style key
  /GROQ_API_KEY|OPENAI_API_KEY|RATE_LIMIT_SECRET/,
  /process\.env\.[A-Z_]+/,
];

export interface OutputGuardResult {
  safe: boolean;
  reason?: string;
}

/**
 * Inspect model output for canary / secret leakage before returning it.
 */
export function outputGuard(output: string, canary: string): OutputGuardResult {
  if (output.includes(canary)) {
    return { safe: false, reason: "Canary token leaked in output — response blocked." };
  }
  for (const re of SECRET_PATTERNS) {
    if (re.test(output)) {
      return { safe: false, reason: "Secret / credential pattern detected in output — response blocked." };
    }
  }
  return { safe: true };
}
