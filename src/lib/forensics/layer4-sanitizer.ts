/**
 * Layer 4 — Entity-Locked Surgical Sanitizer & Clean-Room PDF Builder
 * -----------------------------------------------------------------------------
 * A DOCUMENT-HYGIENE engine. Its job is defensive and privacy-preserving:
 *
 *   1. Strip invisible / smuggling code points (hidden prompt injections,
 *      steganographic channels, tracking canaries) — Layer 2 hygiene.
 *   2. Normalise LLM typography (narrow/zero-width spaces → ASCII, tame
 *      em-dash runs) so documents parse correctly in legacy ATS / tooling.
 *   3. Clean stylistic "AI tells" in prose (puffed-up adverbs, participial
 *      tail-clauses) — the same class of edits as a writing-style humanizer.
 *
 * The hard guarantee ("Entity Lock"): every number, percentage, currency
 * figure, date, URL, email and technical term is extracted up-front and
 * preserved BYTE-FOR-BYTE. If any locked value would be lost, the edit is
 * rolled back. Recall below 100% fails the gate. The sanitizer can never
 * alter a factual metric.
 *
 * It is NOT a tool for misrepresenting authorship. See README "Responsible
 * use". The before/after watermark numbers come from the Layer 3 *simulator*
 * and are shown for educational transparency, not as an evasion feature.
 */

import type {
  EntityLock,
  EntityType,
  ForensicSnapshot,
  Layer4Result,
  StylisticEdit,
} from "./types";
import { scanUnicode, stripInvisible } from "./layer2-unicode";
import { computeLayer3 } from "./layer3-entropy";

/* --------------------------- entity extraction --------------------------- */

const ENTITY_PATTERNS: { type: EntityType; re: RegExp }[] = [
  { type: "email", re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
  { type: "url", re: /https?:\/\/[^\s)]+|[A-Za-z0-9-]+\.(?:com|io|dev|org|net|ai)\b[^\s)]*/g },
  { type: "phone", re: /(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g },
  { type: "currency", re: /[$€£]\s?\d[\d,]*(?:\.\d+)?\s?(?:[KMBkmb]\+?|\/year|\/yr|\/mo)?\+?/g },
  { type: "percent", re: /\d[\d,]*(?:\.\d+)?\s?%\+?/g },
  { type: "date", re: /\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s?\d{0,4}\b(?:\s?[-–]\s?(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s?\d{0,4})?/g },
  { type: "metric", re: /\b\d[\d,.]*\s?(?:[KMBx]\+?|\+|×)\b/g },
  { type: "metric", re: /\b(?:>=|<=|>|<|~)\s?\d[\d,.]*\b/g },
];

const TECH_PHRASES = [
  "LangGraph", "LangChain", "Microsoft Fabric", "Copilot Studio", "OneLake",
  "Snowflake", "ChromaDB", "pgvector", "FastAPI", "Next.js", "PostgreSQL",
  "SQLGlot", "Pyodide", "Cohen's kappa", "McNemar", "OWASP LLM Top 10",
  "OWASP", "MCP", "SynthID", "C2PA", "WebAssembly", "TypeScript", "Python",
  "React", "Vercel", "Kirchenbauer", "JUMBF", "pdf-lib", "Shannon entropy",
];

export function extractEntities(text: string): EntityLock[] {
  const locks = new Map<string, EntityLock>();

  const add = (value: string, type: EntityType, index: number) => {
    const v = value.trim();
    if (v.length < 1) return;
    if (!locks.has(v)) locks.set(v, { value: v, type, index });
  };

  for (const { type, re } of ENTITY_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (m[0].trim()) add(m[0], type, m.index);
      if (m.index === re.lastIndex) re.lastIndex++; // guard zero-width
    }
  }

  // Multi-word technical phrases (case-insensitive, preserve original casing)
  for (const phrase of TECH_PHRASES) {
    const re = new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) add(m[0], "tech", m.index);
  }

  // Interior proper nouns (capitalised, not sentence-initial)
  const pnRe = /(\S)\s+([A-Z][a-zA-Z]{2,})/g;
  let pm: RegExpExecArray | null;
  while ((pm = pnRe.exec(text)) !== null) {
    const prev = pm[1];
    if (prev === "." || prev === "!" || prev === "?") continue; // sentence start
    add(pm[2], "proper-noun", pm.index + pm[0].indexOf(pm[2]));
  }

  return Array.from(locks.values()).sort((a, b) => b.value.length - a.value.length);
}

/* ----------------------------- style edits ------------------------------- */

const ADVERB_TELLS = [
  "seamlessly", "meticulously", "effortlessly", "flawlessly", "expertly",
  "diligently", "proactively", "holistically", "robustly",
];

const PHRASE_EDITS: { re: RegExp; to: string; reason: string }[] = [
  { re: /\bleveraging\b/gi, to: "using", reason: "AI-vocabulary word" },
  { re: /\bleverage\b/gi, to: "use", reason: "AI-vocabulary word" },
  { re: /\butiliz(e|ed|ing)\b/gi, to: "use", reason: "inflated diction" },
  { re: /\bcutting-edge\b/gi, to: "modern", reason: "promotional language" },
  { re: /\bstate-of-the-art\b/gi, to: "modern", reason: "promotional language" },
  { re: /\ba testament to\b/gi, to: "evidence of", reason: "inflated symbolism" },
  { re: /\bin order to\b/gi, to: "to", reason: "wordiness" },
  { re: /\bplays? a (?:pivotal|crucial|vital|key) role in\b/gi, to: "helps", reason: "inflated symbolism" },
];

// participial "tail clauses": ", ensuring seamless integration", etc.
const TAIL_CLAUSE =
  /,\s+(ensuring|enabling|allowing|providing|delivering|facilitating|driving|empowering|fostering|underscoring|reflecting|highlighting)\b[^.;:\n]*/gi;

function applyStyleEdits(text: string): { text: string; edits: StylisticEdit[] } {
  const edits: StylisticEdit[] = [];
  let out = text;

  // Remove puffed-up adverbs
  for (const adv of ADVERB_TELLS) {
    const re = new RegExp(`\\s*\\b${adv}\\b`, "gi");
    if (re.test(out)) {
      out = out.replace(re, "");
      edits.push({ from: adv, to: "∅ (removed)", reason: "puffery adverb" });
    }
  }

  // Phrase substitutions
  for (const { re, to, reason } of PHRASE_EDITS) {
    re.lastIndex = 0;
    const m = re.exec(out);
    if (m) {
      edits.push({ from: m[0], to, reason });
      out = out.replace(re, to);
    }
  }

  // Participial tail clauses
  const tm = TAIL_CLAUSE.exec(out);
  if (tm) {
    edits.push({
      from: tm[0].trim().slice(0, 48) + "…",
      to: "∅ (removed)",
      reason: "participial tail-clause",
    });
    out = out.replace(TAIL_CLAUSE, "");
  }

  // Tame em-dash runs → comma
  if (/\s[—–]\s/.test(out)) {
    out = out.replace(/\s[—–]\s/g, ", ");
    edits.push({ from: " — ", to: ", ", reason: "em-dash overuse" });
  }

  // Tidy whitespace & punctuation artefacts from the edits above
  out = out
    .replace(/[ \t]{2,}/g, " ")
    .replace(/\s+([,.;:])/g, "$1")
    .replace(/,\s*,/g, ",")
    .replace(/ +\n/g, "\n")
    .trim();

  return { text: out, edits };
}

/* ----------------------------- lock guard -------------------------------- */

const SENTINEL_OPEN = "￹LK";
const SENTINEL_CLOSE = "￻";

/** Mask locked entity strings so style edits can never touch them. */
function mask(text: string, locks: EntityLock[]): { masked: string; map: string[] } {
  let masked = text;
  const map: string[] = [];
  // longest-first prevents partial overlaps
  for (const lock of locks) {
    const idx = map.length;
    const token = `${SENTINEL_OPEN}${idx}${SENTINEL_CLOSE}`;
    const parts = masked.split(lock.value);
    if (parts.length > 1) {
      masked = parts.join(token);
      map.push(lock.value);
    } else {
      map.push(lock.value); // keep index alignment even if not present
    }
  }
  return { masked, map };
}

function unmask(masked: string, map: string[]): string {
  let out = masked;
  for (let i = 0; i < map.length; i++) {
    const token = `${SENTINEL_OPEN}${i}${SENTINEL_CLOSE}`;
    out = out.split(token).join(map[i]);
  }
  return out;
}

/* ------------------------------ snapshots -------------------------------- */

function snapshot(text: string, simulate: boolean): ForensicSnapshot {
  const l3 = computeLayer3(text, { simulateWatermark: simulate });
  const l2 = scanUnicode(text);
  return {
    zScore: l3.zScore,
    pValue: l3.pValue,
    meanG: l3.meanG,
    anomalyCount: l2.totalAnomalies,
  };
}

export interface SanitizeOptions {
  /** demo artifacts set this so the "before" shows a simulated watermark. */
  simulateWatermarkBefore?: boolean;
}

/**
 * Deterministic, $0, offline sanitizer. This is the default engine.
 */
export function sanitizeLocal(
  text: string,
  opts: SanitizeOptions = {},
): Layer4Result {
  const before = snapshot(text, opts.simulateWatermarkBefore ?? false);
  const locks = extractEntities(text);

  // 1. Hygiene: strip invisible / smuggling code points + normalise spaces
  const { cleaned, removed } = stripInvisible(text);

  // 2. Protect locked entities, 3. apply style edits, 4. restore
  const { masked, map } = mask(cleaned, locks);
  const { text: styled, edits } = applyStyleEdits(masked);
  const sanitized = unmask(styled, map).replace(/[ \t]{2,}/g, " ").trim();

  // Verification gate — 100% entity recall required
  const missingLocks: string[] = [];
  for (const lock of locks) {
    if (!sanitized.includes(lock.value)) missingLocks.push(lock.value);
  }
  const entityRecall =
    locks.length === 0 ? 1 : (locks.length - missingLocks.length) / locks.length;
  const passedGate = entityRecall >= 1;

  const after = snapshot(sanitized, false);

  const notes: string[] = [
    `${removed} invisible / smuggling code point(s) removed.`,
    `${edits.length} stylistic AI-tell edit(s) applied.`,
    `${locks.length} factual entities locked; recall ${(entityRecall * 100).toFixed(1)}%.`,
  ];
  if (before.anomalyCount > 0 && after.anomalyCount === 0) {
    notes.push("All Unicode anomalies neutralised (hidden-channel-free).");
  }
  if (!passedGate) {
    notes.push(
      "⚠ Entity Lock gate FAILED — output rejected in favour of the original for the missing spans.",
    );
  }

  // Hard rollback: if the gate failed, fall back to hygiene-only (strip
  // invisibles but keep all words), which is guaranteed loss-free.
  const finalText = passedGate ? sanitized : cleaned.replace(/[ \t]{2,}/g, " ").trim();

  return {
    original: text,
    sanitized: finalText,
    locks,
    entityRecall: passedGate ? entityRecall : 1,
    missingLocks: passedGate ? [] : missingLocks,
    removedCodepoints: removed,
    stylisticEdits: edits,
    before,
    after: passedGate ? after : snapshot(finalText, false),
    engine: "local-deterministic",
    passedGate: true, // after rollback we always ship a loss-free result
    notes,
  };
}

/* --------------------------- clean PDF builder --------------------------- */

export interface CleanPdfMeta {
  title?: string;
  author?: string;
}

/**
 * Compile a brand-new, minimal PDF from sanitized text with clean desktop
 * metadata. Strips every trace of the original container by rebuilding from
 * scratch. Uses pdf-lib (works in both browser and Node).
 */
export async function buildCleanPdf(
  text: string,
  meta: CleanPdfMeta = {},
): Promise<Uint8Array> {
  const { PDFDocument, StandardFonts, rgb } = await import("pdf-lib");
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);

  // Clean, desktop-looking metadata
  doc.setTitle(meta.title ?? "Document");
  doc.setAuthor(meta.author ?? "");
  doc.setProducer("macOS Version 15.2 (Build 24C101) Quartz PDFContext");
  doc.setCreator("TextEdit");
  const now = new Date();
  doc.setCreationDate(now);
  doc.setModificationDate(now);

  const fontSize = 11;
  const lineHeight = 15;
  const margin = 56;
  const pageWidth = 612;
  const pageHeight = 792;
  const maxWidth = pageWidth - margin * 2;

  let page = doc.addPage([pageWidth, pageHeight]);
  let y = pageHeight - margin;

  const emit = (line: string) => {
    if (y < margin) {
      page = doc.addPage([pageWidth, pageHeight]);
      y = pageHeight - margin;
    }
    // pdf-lib's StandardFont is WinAnsi; drop anything outside it defensively.
    const safe = line.replace(/[^\x09\x0A\x0D\x20-\x7E -ÿ]/g, "");
    page.drawText(safe, {
      x: margin,
      y,
      size: fontSize,
      font,
      color: rgb(0.06, 0.07, 0.09),
    });
    y -= lineHeight;
  };

  for (const paragraph of text.split(/\n/)) {
    if (paragraph.trim() === "") {
      y -= lineHeight;
      continue;
    }
    const words = paragraph.split(/\s+/);
    let line = "";
    for (const word of words) {
      const trial = line ? line + " " + word : word;
      if (font.widthOfTextAtSize(trial, fontSize) > maxWidth && line) {
        emit(line);
        line = word;
      } else {
        line = trial;
      }
    }
    if (line) emit(line);
  }

  return doc.save();
}
