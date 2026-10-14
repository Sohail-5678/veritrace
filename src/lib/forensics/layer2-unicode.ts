/**
 * Layer 2 — Unicode Steganography & ASCII-Smuggling Scanner
 * -----------------------------------------------------------------------------
 * Walks every code point in the document and classifies invisible / deceptive
 * characters into human-readable findings:
 *   - Zero-width & formatting steganography (ZWSP, ZWNJ, ZWJ, WJ, BOM ...)
 *   - Unicode "Tag" block (U+E0000–U+E007F) ASCII-smuggling — the vector used
 *     to hide invisible prompt-injections inside otherwise clean text. We also
 *     DECODE any smuggled payload so the user can read exactly what was hidden.
 *   - Variation selectors (U+FE00–U+FE0F, U+E0100–U+E01EF)
 *   - Narrow / non-breaking spaces (U+202F, U+00A0) — modern LLM typography
 *   - Em-dash density (U+2014) — a stylistic tell, not a threat
 *   - Mixed-script homoglyphs (Cyrillic / Greek letters inside Latin words)
 *
 * This is a DETECTOR. Removing these characters (the `strip*` helpers) is a
 * defensive hygiene step: it neutralises hidden injections and tracking
 * channels before any text is shown or forwarded.
 */

import type {
  HomoglyphHit,
  Layer2Result,
  Severity,
  UnicodeCategory,
  UnicodeFinding,
} from "./types";

interface CodepointSpec {
  name: string;
  category: UnicodeCategory;
  severity: Severity;
  note: string;
}

/** Individually named suspicious code points. */
const CODEPOINTS: Record<number, CodepointSpec> = {
  0x200b: {
    name: "Zero-Width Space",
    category: "zero-width",
    severity: "threat",
    note: "Invisible. Commonly used as a binary canary / steganographic channel.",
  },
  0x200c: {
    name: "Zero-Width Non-Joiner",
    category: "zero-width",
    severity: "threat",
    note: "Invisible control character usable for hidden binary encoding.",
  },
  0x200d: {
    name: "Zero-Width Joiner",
    category: "zero-width",
    severity: "threat",
    note: "Invisible. Can smuggle data or alter emoji rendering.",
  },
  0x2060: {
    name: "Word Joiner",
    category: "zero-width",
    severity: "threat",
    note: "Invisible glue character — viable covert channel.",
  },
  0xfeff: {
    name: "Zero-Width No-Break Space / BOM",
    category: "bom",
    severity: "caution",
    note: "Byte-order mark mid-document is anomalous; can hide data.",
  },
  0x180e: {
    name: "Mongolian Vowel Separator",
    category: "zero-width",
    severity: "threat",
    note: "Deprecated invisible separator — classic smuggling character.",
  },
  0x00ad: {
    name: "Soft Hyphen",
    category: "soft-hyphen",
    severity: "caution",
    note: "Invisible unless line breaks there — can fragment keyword matching.",
  },
  0x200e: {
    name: "Left-to-Right Mark",
    category: "zero-width",
    severity: "caution",
    note: "Invisible bidi control.",
  },
  0x200f: {
    name: "Right-to-Left Mark",
    category: "zero-width",
    severity: "caution",
    note: "Invisible bidi control — can visually reorder text.",
  },
  0x202f: {
    name: "Narrow No-Break Space",
    category: "narrow-nbsp",
    severity: "caution",
    note: "Heavily emitted by modern LLMs before units/punctuation; breaks legacy ATS parsers.",
  },
  0x00a0: {
    name: "No-Break Space",
    category: "nbsp",
    severity: "caution",
    note: "Non-standard space that survives copy/paste and confuses parsers.",
  },
};

const TAG_START = 0xe0000;
const TAG_END = 0xe007f;

function isVariationSelector(cp: number): boolean {
  return (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
}

/** Cyrillic / Greek → Latin homoglyph map. */
const HOMOGLYPHS: Record<string, { latin: string; script: string }> = {
  а: { latin: "a", script: "Cyrillic" },
  е: { latin: "e", script: "Cyrillic" },
  о: { latin: "o", script: "Cyrillic" },
  р: { latin: "p", script: "Cyrillic" },
  с: { latin: "c", script: "Cyrillic" },
  х: { latin: "x", script: "Cyrillic" },
  у: { latin: "y", script: "Cyrillic" },
  і: { latin: "i", script: "Cyrillic" },
  ј: { latin: "j", script: "Cyrillic" },
  ѕ: { latin: "s", script: "Cyrillic" },
  А: { latin: "A", script: "Cyrillic" },
  В: { latin: "B", script: "Cyrillic" },
  Е: { latin: "E", script: "Cyrillic" },
  К: { latin: "K", script: "Cyrillic" },
  М: { latin: "M", script: "Cyrillic" },
  Н: { latin: "H", script: "Cyrillic" },
  О: { latin: "O", script: "Cyrillic" },
  Р: { latin: "P", script: "Cyrillic" },
  С: { latin: "C", script: "Cyrillic" },
  Т: { latin: "T", script: "Cyrillic" },
  Х: { latin: "X", script: "Cyrillic" },
  ο: { latin: "o", script: "Greek" },
  Ο: { latin: "O", script: "Greek" },
  Α: { latin: "A", script: "Greek" },
  Ε: { latin: "E", script: "Greek" },
  Ρ: { latin: "P", script: "Greek" },
  Τ: { latin: "T", script: "Greek" },
};

const MAX_POSITIONS = 16;

export function scanUnicode(text: string): Layer2Result {
  const buckets = new Map<
    number,
    { spec: CodepointSpec; count: number; positions: number[] }
  >();
  const tagRuns: { chars: number[]; at: number }[] = [];
  let currentTagRun: { chars: number[]; at: number } | null = null;

  let offset = 0;
  let emDashCount = 0;
  let variationCount = 0;
  const variationPositions: number[] = [];

  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    const width = cp > 0xffff ? 2 : 1; // UTF-16 code units

    if (cp === 0x2014) emDashCount++;

    // Tag block (ASCII smuggling)
    if (cp >= TAG_START && cp <= TAG_END) {
      if (!currentTagRun) {
        currentTagRun = { chars: [], at: offset };
        tagRuns.push(currentTagRun);
      }
      currentTagRun.chars.push(cp);
      bump(buckets, cp, {
        name: "Unicode Tag Character",
        category: "tag",
        severity: "threat",
        note: "Invisible 'tag' code point — the primary ASCII-smuggling vector for hidden prompt injection.",
      }, offset);
      offset += width;
      continue;
    } else {
      currentTagRun = null;
    }

    // Variation selectors
    if (isVariationSelector(cp)) {
      variationCount++;
      if (variationPositions.length < MAX_POSITIONS) variationPositions.push(offset);
      offset += width;
      continue;
    }

    // Named suspicious code points
    const spec = CODEPOINTS[cp];
    if (spec) {
      bump(buckets, cp, spec, offset);
    }

    offset += width;
  }

  const findings: UnicodeFinding[] = [];
  for (const [cp, data] of buckets) {
    findings.push({
      codepoint: cp,
      label: toLabel(cp),
      name: data.spec.name,
      category: data.spec.category,
      severity: data.spec.severity,
      count: data.count,
      positions: data.positions,
      note: data.spec.note,
    });
  }

  if (variationCount > 0) {
    findings.push({
      codepoint: 0xfe00,
      label: "U+FE00–U+E01EF",
      name: "Variation Selector(s)",
      category: "variation-selector",
      severity: "threat",
      count: variationCount,
      positions: variationPositions,
      note: "Variation selectors can carry a hidden data channel appended to visible glyphs.",
    });
  }

  // Em-dash density (stylistic tell, not a threat)
  const wordCount = Math.max(1, text.split(/\s+/).filter(Boolean).length);
  const emDashDensityPer500 = (emDashCount / wordCount) * 500;
  if (emDashCount > 0) {
    findings.push({
      codepoint: 0x2014,
      label: "U+2014",
      name: "Em Dash",
      category: "em-dash",
      severity: emDashDensityPer500 > 2.5 ? "caution" : "clean",
      count: emDashCount,
      positions: [],
      note:
        emDashDensityPer500 > 2.5
          ? `High density (${emDashDensityPer500.toFixed(1)}/500 words) — a common generated-text tell.`
          : "Within normal range.",
    });
  }

  // Decode any smuggled tag payload
  let decoded = "";
  for (const run of tagRuns) {
    for (const cp of run.chars) {
      const ascii = cp - TAG_START;
      if (ascii >= 0x20 && ascii <= 0x7e) decoded += String.fromCharCode(ascii);
    }
  }
  const decodedHiddenMessage = decoded.length >= 3 ? decoded : null;

  // Homoglyphs
  const homoglyphHits = findHomoglyphs(text);
  if (homoglyphHits.length > 0) {
    const byScript = new Map<string, number>();
    for (const h of homoglyphHits)
      byScript.set(h.script, (byScript.get(h.script) ?? 0) + 1);
    findings.push({
      codepoint: 0x0430,
      label: "mixed-script",
      name: "Homoglyph Substitution",
      category: "homoglyph",
      severity: "threat",
      count: homoglyphHits.length,
      positions: homoglyphHits.slice(0, MAX_POSITIONS).map((h) => h.index),
      note:
        "Non-Latin letters disguised as Latin (" +
        Array.from(byScript.keys()).join(", ") +
        ") — used for spoofing and filter evasion.",
    });
  }

  // Sort: threats first, then by count
  const order: Record<Severity, number> = { threat: 0, caution: 1, clean: 2 };
  findings.sort(
    (a, b) => order[a.severity] - order[b.severity] || b.count - a.count,
  );

  const threatCount = findings
    .filter((f) => f.severity === "threat")
    .reduce((n, f) => n + f.count, 0);
  const totalAnomalies = findings
    .filter((f) => f.severity !== "clean")
    .reduce((n, f) => n + f.count, 0);

  return {
    findings,
    totalAnomalies,
    threatCount,
    decodedHiddenMessage,
    homoglyphHits,
    emDashDensityPer500: Number(emDashDensityPer500.toFixed(2)),
  };
}

function bump(
  buckets: Map<number, { spec: CodepointSpec; count: number; positions: number[] }>,
  cp: number,
  spec: CodepointSpec,
  offset: number,
) {
  const existing = buckets.get(cp);
  if (existing) {
    existing.count++;
    if (existing.positions.length < MAX_POSITIONS) existing.positions.push(offset);
  } else {
    buckets.set(cp, { spec, count: 1, positions: [offset] });
  }
}

function toLabel(cp: number): string {
  return "U+" + cp.toString(16).toUpperCase().padStart(4, "0");
}

export function findHomoglyphs(text: string): HomoglyphHit[] {
  const hits: HomoglyphHit[] = [];
  const wordRe = /[\p{L}][\p{L}\d'-]*/gu;
  let m: RegExpExecArray | null;
  while ((m = wordRe.exec(text)) !== null) {
    const word = m[0];
    let hasLatin = false;
    let hasHomoglyph = false;
    let script = "";
    let normalized = "";
    for (const ch of word) {
      if (/[A-Za-z]/.test(ch)) hasLatin = true;
      const hg = HOMOGLYPHS[ch];
      if (hg) {
        hasHomoglyph = true;
        script = hg.script;
        normalized += hg.latin;
      } else {
        normalized += ch;
      }
    }
    if (hasLatin && hasHomoglyph) {
      hits.push({ word, normalized, index: m.index, script });
    }
  }
  return hits;
}

/**
 * Defensive hygiene: remove invisible / smuggling code points, normalise
 * exotic spaces to ASCII 0x20, and fold homoglyphs back to Latin. Returns the
 * cleaned text and the number of code points removed/normalised.
 */
export function stripInvisible(text: string): {
  cleaned: string;
  removed: number;
} {
  let removed = 0;
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;

    // Drop tag block, variation selectors, zero-width & formatting controls
    if (
      (cp >= TAG_START && cp <= TAG_END) ||
      isVariationSelector(cp) ||
      cp === 0x200b ||
      cp === 0x200c ||
      cp === 0x200d ||
      cp === 0x2060 ||
      cp === 0xfeff ||
      cp === 0x180e ||
      cp === 0x00ad ||
      cp === 0x200e ||
      cp === 0x200f ||
      cp === 0x061c ||
      (cp >= 0x2061 && cp <= 0x2064)
    ) {
      removed++;
      continue;
    }

    // Normalise exotic spaces
    if (cp === 0x202f || cp === 0x00a0 || cp === 0x2009 || cp === 0x2007) {
      out += " ";
      removed++;
      continue;
    }

    // Fold homoglyphs
    const hg = HOMOGLYPHS[ch];
    if (hg) {
      out += hg.latin;
      removed++;
      continue;
    }

    out += ch;
  }
  return { cleaned: out, removed };
}
