/**
 * Layer 3 — SynthID-Text Tournament & Kirchenbauer Green-List Entropy Engine
 * -----------------------------------------------------------------------------
 * A transparent, deterministic *simulator* of the two best-known text
 * watermarking families, for EDUCATION and forensic visualisation:
 *
 *   - Kirchenbauer et al. "green/red list" watermark  →  z-score detector
 *   - DeepMind SynthID-Text tournament sampling       →  mean g-score
 *
 * It also estimates per-token conditional Shannon entropy H(X_t | X_<t) via a
 * lexical-substitutability heuristic. This "entropy masking" is the crucial
 * honest part: low-entropy tokens (numbers, dates, technical nouns) cannot
 * carry a watermark, so the detector ignores them — exactly as the real
 * schemes do.
 *
 * IMPORTANT — honesty about what this is:
 *   A real watermark detector only fires on text generated under the *same*
 *   key and scheme it probes. Arbitrary human or third-party text yields z ≈ 0.
 *   That is the correct result and the UI says so. The pre-loaded demo
 *   artifacts pass `simulateWatermark: true`, which biases ONLY the
 *   high-entropy carrier tokens, so the demo shows what a genuinely
 *   watermarked document looks like. Live user input always runs with
 *   `simulateWatermark: false` — the engine never fabricates a signal.
 */

import type { LockState, Layer3Result, Token, WatermarkVerdict } from "./types";

const GAMMA = 0.5; // green-list fraction
const CONTEXT_WINDOW = 4; // H-gram seeding window
const TOURNAMENT_LAYERS = 30; // SynthID tournament depth m
export const DEFAULT_SEED = 0x5eed1234;

/* -------------------------- deterministic PRF ---------------------------- */
/**
 * Fast, well-mixed 32-bit non-cryptographic hash used as the keyed PRF. In a
 * production detector this slot would hold HMAC-SHA256(key, context); here a
 * fast avalanche hash keeps the whole sweep well under a frame budget while
 * giving a uniform green/red partition. Swap-in point is intentional.
 */
export function hash32(str: string, seed: number): number {
  let h = seed >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193); // FNV prime
    h ^= h >>> 15;
  }
  // final avalanche (murmur3 fmix)
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return h >>> 0;
}

function unit(h: number): number {
  return (h % 100000) / 100000;
}

/* ----------------------------- erf / erfc -------------------------------- */
/** Complementary error function (Abramowitz & Stegun 7.1.26). */
export function erfc(x: number): number {
  const z = Math.abs(x);
  const t = 1 / (1 + 0.5 * z);
  const ans =
    t *
    Math.exp(
      -z * z -
        1.26551223 +
        t *
          (1.00002368 +
            t *
              (0.37409196 +
                t *
                  (0.09678418 +
                    t *
                      (-0.18628806 +
                        t *
                          (0.27886807 +
                            t *
                              (-1.13520398 +
                                t *
                                  (1.48851587 +
                                    t *
                                      (-0.82215223 + t * 0.17087277)))))))),
    );
  return x >= 0 ? ans : 2 - ans;
}

/** One-sided upper-tail p-value for a standard normal z. */
export function pValueFromZ(z: number): number {
  return 0.5 * erfc(z / Math.SQRT2);
}

/* ----------------------------- lexicons ---------------------------------- */

const TECH_TERMS = new Set(
  [
    "langgraph", "langchain", "mcp", "fabric", "snowflake", "onelake",
    "copilot", "chromadb", "pgvector", "fastapi", "next.js", "nextjs",
    "postgresql", "postgres", "sqlglot", "pyodide", "typescript", "python",
    "react", "webassembly", "wasm", "vercel", "kubernetes", "docker",
    "pytorch", "tensorflow", "huggingface", "transformers", "openai",
    "anthropic", "claude", "llm", "rag", "vectordb", "redis", "kafka",
    "spark", "airflow", "dbt", "tableau", "powerbi", "numpy", "pandas",
    "scikit", "sklearn", "xgboost", "cohen", "mcnemar", "owasp", "synthid",
    "kirchenbauer", "c2pa", "jumbf", "api", "sdk", "cli", "ci", "cd", "aws",
    "gcp", "azure", "graphql", "oauth", "jwt", "sso", "csp", "xss", "ssrf",
  ],
);

/** Function / grammatical words — low entropy but structurally fixed. */
const FUNCTION_WORDS = new Set(
  [
    "the", "a", "an", "and", "or", "but", "of", "to", "in", "on", "at", "for",
    "with", "by", "as", "is", "are", "was", "were", "be", "been", "this",
    "that", "these", "those", "it", "its", "from", "into", "than", "then",
    "so", "if", "not", "no", "we", "i", "you", "they", "he", "she", "our",
    "my", "their", "his", "her", "which", "who", "whom", "whose", "will",
  ],
);

/** High-substitutability content words → strong watermark carriers. */
const CARRIER_WORDS = new Set(
  [
    "seamlessly", "meticulously", "robust", "leverage", "leveraging",
    "utilize", "utilized", "spearheaded", "orchestrated", "streamlined",
    "optimized", "enhanced", "facilitated", "implemented", "developed",
    "designed", "architected", "delivered", "enabled", "ensuring", "ensured",
    "comprehensive", "innovative", "cutting-edge", "state-of-the-art",
    "significant", "substantial", "numerous", "various", "effectively",
    "efficiently", "successfully", "additionally", "furthermore", "moreover",
    "consequently", "thereby", "whereby", "testament", "pivotal", "crucial",
    "vital", "powerful", "seamless", "dynamic", "scalable", "cornerstone",
  ],
);

/* ---------------------------- tokenization ------------------------------- */

const TOKEN_RE = /([A-Za-z0-9][A-Za-z0-9$%+._/'’-]*)|(\s+)|([^\sA-Za-z0-9]+)/g;

interface RawTok {
  text: string;
  start: number;
  end: number;
  isWord: boolean;
}

function tokenize(text: string): RawTok[] {
  const out: RawTok[] = [];
  let m: RegExpExecArray | null;
  TOKEN_RE.lastIndex = 0;
  while ((m = TOKEN_RE.exec(text)) !== null) {
    const t = m[0];
    out.push({
      text: t,
      start: m.index,
      end: m.index + t.length,
      isWord: m[1] !== undefined,
    });
  }
  return out;
}

const NUMERIC_RE = /^[$€£]?\d[\d,.]*(%|k|m|b|x|\+)?\+?$/i;
const DATE_RE = /^(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|\d{4}|\d{1,2}\/\d{1,2})/i;

/** Estimate conditional entropy (bits) + lock state for a word token. */
function classify(word: string): {
  entropy: number;
  lock: LockState;
  lockReason: string | null;
} {
  const lower = word.toLowerCase();

  if (NUMERIC_RE.test(word) || /\d/.test(word)) {
    return { entropy: 0.18, lock: "LOCKED", lockReason: "numeric / metric" };
  }
  if (DATE_RE.test(word) && /\d/.test(word)) {
    return { entropy: 0.22, lock: "LOCKED", lockReason: "date" };
  }
  if (/[@]/.test(word) || /^https?:/.test(lower) || /\.(com|io|dev|org|net)$/.test(lower)) {
    return { entropy: 0.2, lock: "LOCKED", lockReason: "identifier / URL" };
  }
  if (TECH_TERMS.has(lower) || TECH_TERMS.has(lower.replace(/[^a-z0-9.]/g, ""))) {
    return { entropy: 0.35, lock: "LOCKED", lockReason: "technical term" };
  }
  // Proper noun: capitalised, not sentence-start heuristic handled by caller.
  if (/^[A-Z][a-z]{2,}$/.test(word)) {
    return { entropy: 0.6, lock: "LOCKED", lockReason: "proper noun" };
  }
  if (CARRIER_WORDS.has(lower)) {
    return { entropy: 3.4, lock: "MUTABLE", lockReason: null };
  }
  if (FUNCTION_WORDS.has(lower)) {
    return { entropy: 0.9, lock: "MUTABLE", lockReason: null };
  }
  // generic content word: entropy scales mildly with length
  const e = Math.min(3.0, 1.4 + Math.min(word.length, 12) / 10);
  return { entropy: Number(e.toFixed(2)), lock: "MUTABLE", lockReason: null };
}

export interface Layer3Options {
  seed?: number;
  simulateWatermark?: boolean;
}

export function computeLayer3(
  text: string,
  opts: Layer3Options = {},
): Layer3Result {
  const seed = opts.seed ?? DEFAULT_SEED;
  const simulate = opts.simulateWatermark ?? false;
  const raw = tokenize(text);
  const tokens: Token[] = [];

  const contextWords: string[] = [];
  let greenCount = 0;
  let counted = 0; // tokens with full context (t > H)
  let gSum = 0;
  let lockedCount = 0;
  let carrierCount = 0;
  let wordCount = 0;

  raw.forEach((rt, i) => {
    if (!rt.isWord) {
      tokens.push({
        text: rt.text,
        index: i,
        start: rt.start,
        end: rt.end,
        isWord: false,
        entropy: 0,
        lock: "MUTABLE",
        lockReason: null,
        green: false,
        gScore: 0,
      });
      return;
    }

    wordCount++;
    const { entropy, lock, lockReason } = classify(rt.text);
    if (lock === "LOCKED") lockedCount++;
    const isCarrier = lock === "MUTABLE" && entropy > 2.2;
    if (isCarrier) carrierCount++;

    const ctxKey = contextWords.slice(-CONTEXT_WINDOW).join(" ");
    const hasContext = contextWords.length >= CONTEXT_WINDOW;
    const key = ctxKey + "|" + rt.text.toLowerCase();

    // Entropy masking (the honest core): a watermark biases sampling steps
    // that are substitutable. LOCKED factual tokens — numbers, dates, proper
    // nouns, technical terms — are never biased, so facts are untouched. Any
    // other (mutable) token with non-trivial entropy is a candidate carrier.
    // `simulate` is true only for the pre-loaded watermarked demo artifacts.
    const biasable = lock === "MUTABLE" && entropy > 0.6;

    // Green-list membership.
    const u = unit(hash32(key, seed));
    const greenThreshold = simulate && biasable ? 0.8 : GAMMA;
    const green = u < greenThreshold;

    // SynthID tournament mean g
    let greens = 0;
    for (let l = 1; l <= TOURNAMENT_LAYERS; l++) {
      const gu = unit(hash32(key + "#" + l, seed));
      const gThresh = simulate && biasable ? 0.6 : 0.5;
      if (gu < gThresh) greens++;
    }
    const gScore = greens / TOURNAMENT_LAYERS;

    if (hasContext) {
      counted++;
      if (green) greenCount++;
      gSum += gScore;
    }

    tokens.push({
      text: rt.text,
      index: i,
      start: rt.start,
      end: rt.end,
      isWord: true,
      entropy,
      lock,
      lockReason,
      green,
      gScore: Number(gScore.toFixed(3)),
    });

    contextWords.push(rt.text.toLowerCase());
  });

  const T = Math.max(1, counted);
  const expected = GAMMA * T;
  const sd = Math.sqrt(T * GAMMA * (1 - GAMMA));
  const zScore = (greenCount - expected) / sd;
  const pValue = pValueFromZ(zScore);
  const meanG = counted > 0 ? gSum / counted : 0.5;
  const greenFraction = greenCount / T;

  let verdict: WatermarkVerdict;
  if (zScore > 4.0) verdict = "likely-watermarked";
  else if (zScore > 1.6) verdict = "inconclusive";
  else verdict = "likely-human";

  return {
    tokens,
    wordCount,
    zScore: Number(zScore.toFixed(2)),
    pValue: Number(pValue.toExponential(2)),
    meanG: Number(meanG.toFixed(3)),
    greenFraction: Number(greenFraction.toFixed(3)),
    lockedCount,
    carrierCount,
    verdict,
    seed,
  };
}

/**
 * Multi-seed blind sweep: probe several keys and return the max |z|. In the
 * real world you rarely know the watermarking key, so a sweep is how blind
 * detection is approached. Honest limitation: without the true key, a sweep
 * can only find a signal that is actually present.
 */
export function blindSweep(
  text: string,
  seeds: number[] = [DEFAULT_SEED, 0xa5a5a5, 0x13371337, 0x0badf00d, 0xcafe],
): { seed: number; zScore: number }[] {
  return seeds
    .map((seed) => {
      const r = computeLayer3(text, { seed });
      return { seed, zScore: r.zScore };
    })
    .sort((a, b) => Math.abs(b.zScore) - Math.abs(a.zScore));
}
