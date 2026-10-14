/**
 * Security Guardrail #4 — Binary File-Bomb & Polyglot Firewall
 * -----------------------------------------------------------------------------
 * Validates untrusted uploads BEFORE any parsing:
 *   - Strict magic-byte verification (declared type must match real bytes)
 *   - Hard size caps (Vercel-safe payload limit + text length limit)
 *   - UTF-8 validity check for text
 *   - A conservative decompression-ratio guard for ZIP/DOCX containers
 *   - Enumerates PDF active-content keys so callers can defang them
 */

import { detectFileType } from "../forensics/layer1-binary";
import type { FileType } from "../forensics/types";

export const MAX_FILE_BYTES = 4.5 * 1024 * 1024; // 4.5 MB
export const MAX_TEXT_CHARS = 50_000;

export interface FirewallResult {
  ok: boolean;
  fileType: FileType;
  byteLength: number;
  reason?: string;
  blockedKeys?: string[];
}

const DANGEROUS_PDF_KEYS = [
  "/JavaScript",
  "/JS",
  "/OpenAction",
  "/AA",
  "/Launch",
  "/RichMedia",
  "/EmbeddedFile",
  "/XFA",
];

/** Validate raw uploaded bytes. */
export function validateUpload(
  bytes: Uint8Array,
  declaredType?: FileType,
): FirewallResult {
  if (bytes.length === 0) {
    return { ok: false, fileType: "unknown", byteLength: 0, reason: "Empty file." };
  }
  if (bytes.length > MAX_FILE_BYTES) {
    return {
      ok: false,
      fileType: "unknown",
      byteLength: bytes.length,
      reason: `File exceeds ${(MAX_FILE_BYTES / 1024 / 1024).toFixed(1)} MB limit.`,
    };
  }

  const realType = detectFileType(bytes);

  // Declared vs real mismatch → possible polyglot / spoof
  if (declaredType && declaredType !== "text" && declaredType !== realType) {
    return {
      ok: false,
      fileType: realType,
      byteLength: bytes.length,
      reason: `Declared ${declaredType} but magic bytes indicate ${realType} (possible polyglot).`,
    };
  }

  if (realType === "pdf") {
    const head = new TextDecoder("latin1").decode(bytes);
    const blockedKeys = DANGEROUS_PDF_KEYS.filter((k) => head.includes(k));
    return { ok: true, fileType: "pdf", byteLength: bytes.length, blockedKeys };
  }

  if (realType === "docx") {
    // Conservative zip-bomb guard: refuse absurd declared sizes in the
    // local file headers (uncompressed-size field) relative to payload.
    const ratio = estimateZipExpansion(bytes);
    if (ratio > 250) {
      return {
        ok: false,
        fileType: "docx",
        byteLength: bytes.length,
        reason: `Suspicious compression ratio (~${ratio.toFixed(0)}x) — possible zip bomb.`,
      };
    }
    return { ok: true, fileType: "docx", byteLength: bytes.length };
  }

  // Treat as text: must be valid UTF-8
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return {
      ok: false,
      fileType: "unknown",
      byteLength: bytes.length,
      reason: "Not valid UTF-8 text and not a recognised document container.",
    };
  }
  return { ok: true, fileType: "text", byteLength: bytes.length };
}

/** Validate pasted / typed text. */
export function validateText(text: string): {
  ok: boolean;
  reason?: string;
} {
  if (text.length === 0) return { ok: false, reason: "Empty input." };
  if (text.length > MAX_TEXT_CHARS) {
    return {
      ok: false,
      reason: `Text exceeds ${MAX_TEXT_CHARS.toLocaleString()} character limit.`,
    };
  }
  return { ok: true };
}

/**
 * Sum the uncompressed-size fields from ZIP local file headers and compare to
 * the archive size. A cheap heuristic — no actual inflation is performed.
 */
function estimateZipExpansion(bytes: Uint8Array): number {
  let uncompressed = 0;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let i = 0; i + 30 < bytes.length && i < 2_000_000; ) {
    // local file header signature 0x04034b50 (little-endian)
    if (
      bytes[i] === 0x50 &&
      bytes[i + 1] === 0x4b &&
      bytes[i + 2] === 0x03 &&
      bytes[i + 3] === 0x04
    ) {
      const uncompSize = view.getUint32(i + 22, true);
      const nameLen = view.getUint16(i + 26, true);
      const extraLen = view.getUint16(i + 28, true);
      const compSize = view.getUint32(i + 18, true);
      uncompressed += uncompSize;
      i += 30 + nameLen + extraLen + compSize;
      if (compSize === 0) i += 1; // avoid infinite loop on streamed entries
    } else {
      i++;
    }
  }
  if (uncompressed === 0) return 1;
  return uncompressed / bytes.length;
}
