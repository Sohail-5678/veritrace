import { describe, it, expect } from "vitest";
import { detectFileType, inspectBinary } from "@/lib/forensics/layer1-binary";
import { scanUnicode, stripInvisible, findHomoglyphs } from "@/lib/forensics/layer2-unicode";
import {
  computeLayer3,
  erfc,
  pValueFromZ,
  blindSweep,
} from "@/lib/forensics/layer3-entropy";
import { sanitizeLocal, extractEntities } from "@/lib/forensics/layer4-sanitizer";

const enc = (s: string) => new TextEncoder().encode(s);

describe("Layer 1 — binary forensics", () => {
  it("detects PDF and DOCX magic bytes", () => {
    expect(detectFileType(new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]))).toBe("pdf");
    expect(detectFileType(new Uint8Array([0x50, 0x4b, 0x03, 0x04]))).toBe("docx");
    expect(detectFileType(enc("just text"))).toBe("text");
  });

  it("flags a headless-container producer", () => {
    const pdf = "%PDF-1.7\n/Producer (Skia/PDF m128 Google Docs Renderer)\n/BaseFont /DejaVuSans\n/OpenAction 1 0 R";
    const r = inspectBinary(enc(pdf));
    expect(r.applicable).toBe(true);
    expect(r.containerRiskScore).toBeGreaterThan(30);
    expect(r.findings.some((f) => /Skia/.test(f.value))).toBe(true);
    expect(r.fonts.some((f) => f.container)).toBe(true);
    expect(r.activeContentKeys).toContain("/OpenAction");
  });

  it("marks plain text as not applicable", () => {
    expect(inspectBinary(enc("hello world")).applicable).toBe(false);
  });
});

describe("Layer 2 — unicode steganography", () => {
  it("detects zero-width and narrow no-break spaces", () => {
    const r = scanUnicode("hello​world there");
    expect(r.totalAnomalies).toBeGreaterThanOrEqual(2);
    expect(r.findings.some((f) => f.codepoint === 0x200b)).toBe(true);
  });

  it("decodes a smuggled Unicode-tag payload", () => {
    const hidden = Array.from("secret")
      .map((c) => String.fromCodePoint(0xe0000 + c.charCodeAt(0)))
      .join("");
    const r = scanUnicode("visible text" + hidden);
    expect(r.decodedHiddenMessage).toBe("secret");
    expect(r.threatCount).toBeGreaterThan(0);
  });

  it("finds Cyrillic homoglyphs inside Latin words", () => {
    const hits = findHomoglyphs("Pа" + "ypal"); // 'а' is Cyrillic
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].normalized.toLowerCase()).toContain("pa");
  });

  it("strips invisible characters losslessly for visible text", () => {
    const dirty = "clean​ te­xt here";
    const { cleaned, removed } = stripInvisible(dirty);
    expect(removed).toBeGreaterThan(0);
    expect(cleaned).not.toMatch(/[​­]/);
    expect(cleaned).toContain("clean");
  });
});

describe("Layer 3 — entropy & watermark simulator", () => {
  it("erfc(0) ≈ 1 and p(z=0) ≈ 0.5", () => {
    expect(erfc(0)).toBeCloseTo(1, 2);
    expect(pValueFromZ(0)).toBeCloseTo(0.5, 2);
  });

  it("human text yields a low z-score", () => {
    const text =
      "The team shipped the project on time and the results were reviewed by the committee before the launch.";
    const r = computeLayer3(text, { simulateWatermark: false });
    expect(Math.abs(r.zScore)).toBeLessThan(3);
    expect(r.verdict).not.toBe("likely-watermarked");
  });

  it("simulated watermark raises the z-score on carrier-heavy text", () => {
    const text =
      "The platform seamlessly leveraging robust comprehensive innovative effectively delivered significant streamlined scalable dynamic results furthermore consequently thereby.";
    const plain = computeLayer3(text, { simulateWatermark: false }).zScore;
    const marked = computeLayer3(text, { simulateWatermark: true }).zScore;
    expect(marked).toBeGreaterThan(plain);
  });

  it("locks low-entropy tokens (numbers / tech terms)", () => {
    const r = computeLayer3("Delivered 97% accuracy using LangGraph and pgvector.");
    const locked = r.tokens.filter((t) => t.lock === "LOCKED");
    expect(locked.length).toBeGreaterThan(0);
  });

  it("blind sweep returns sorted candidates", () => {
    const res = blindSweep("some arbitrary text to probe across seeds");
    expect(res.length).toBeGreaterThan(1);
    expect(Math.abs(res[0].zScore)).toBeGreaterThanOrEqual(Math.abs(res[1].zScore));
  });
});

describe("Layer 4 — sanitizer", () => {
  const sample =
    "Delivered $250K+/year savings with 97%+ accuracy using LangGraph and pgvector, seamlessly ensuring robust integration by Jun 2026.";

  it("extracts factual entities", () => {
    const locks = extractEntities(sample);
    const values = locks.map((l) => l.value);
    expect(values.some((v) => v.includes("$250K+"))).toBe(true);
    expect(values.some((v) => v.includes("97%"))).toBe(true);
    expect(values.some((v) => /LangGraph/i.test(v))).toBe(true);
  });

  it("preserves every locked entity (100% recall)", () => {
    const r = sanitizeLocal(sample);
    expect(r.entityRecall).toBe(1);
    expect(r.passedGate).toBe(true);
    for (const lock of r.locks) {
      expect(r.sanitized).toContain(lock.value);
    }
  });

  it("removes invisible characters and cleans style tells", () => {
    const dirty = sample + "​  meticulously seamlessly";
    const r = sanitizeLocal(dirty);
    expect(r.removedCodepoints).toBeGreaterThan(0);
    expect(r.sanitized).not.toMatch(/[​ ]/);
    expect(r.stylisticEdits.length).toBeGreaterThan(0);
  });
});
