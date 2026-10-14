/**
 * Orchestrator: turn raw text or raw bytes into a full ScanResult.
 * Isomorphic — used by both the browser UI (instant, private) and the API
 * routes (zero-trust server path). Text extraction for .docx and .pdf uses the
 * platform's built-in DecompressionStream, so there are no extra dependencies.
 */

import type { FileType, ScanResult } from "./types";
import { detectFileType, inspectBinary } from "./layer1-binary";
import { scanUnicode } from "./layer2-unicode";
import { computeLayer3 } from "./layer3-entropy";

function now(): number {
  return typeof performance !== "undefined" ? performance.now() : Date.now();
}

/** Analyse plain text (all layers except the binary container). */
export function analyzeText(text: string): ScanResult {
  const start = now();
  const layer2 = scanUnicode(text);
  const layer3 = computeLayer3(text, { simulateWatermark: false });
  const layer1 = inspectBinary(new TextEncoder().encode(text));
  return {
    fileType: "text",
    byteLength: new TextEncoder().encode(text).length,
    textLength: text.length,
    layer1,
    layer2,
    layer3,
    elapsedMs: Number((now() - start).toFixed(1)),
  };
}

/** Analyse raw uploaded bytes: Layer 1 always; Layers 2/3 on extracted text. */
export async function analyzeBytes(
  bytes: Uint8Array,
  fileName = "",
): Promise<ScanResult & { extractedText: string }> {
  const start = now();
  const fileType = detectFileType(bytes);
  const layer1 = inspectBinary(bytes, fileName);

  let extractedText = "";
  try {
    if (fileType === "text") {
      extractedText = new TextDecoder("utf-8").decode(bytes);
    } else if (fileType === "docx") {
      extractedText = await extractDocxText(bytes);
    } else if (fileType === "pdf") {
      extractedText = await extractPdfText(bytes);
    }
  } catch {
    extractedText = "";
  }

  const layer2 = scanUnicode(extractedText);
  const layer3 = computeLayer3(extractedText, { simulateWatermark: false });

  return {
    fileType,
    byteLength: bytes.length,
    textLength: extractedText.length,
    layer1,
    layer2,
    layer3,
    elapsedMs: Number((now() - start).toFixed(1)),
    extractedText,
  };
}

/* --------------------------- decompression ------------------------------- */

async function inflate(
  data: Uint8Array,
  format: "deflate" | "deflate-raw",
): Promise<Uint8Array> {
  const ds = new DecompressionStream(format);
  const stream = new Response(data as BodyInit).body!.pipeThrough(ds);
  const buf = await new Response(stream).arrayBuffer();
  return new Uint8Array(buf);
}

/* ------------------------------- DOCX ------------------------------------ */

/** Minimal ZIP central-directory reader → inflate word/document.xml → text. */
async function extractDocxText(bytes: Uint8Array): Promise<string> {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  // locate End Of Central Directory (0x06054b50)
  let eocd = -1;
  for (let i = bytes.length - 22; i >= 0 && i > bytes.length - 65558; i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return "";

  const entries = view.getUint16(eocd + 10, true);
  let p = view.getUint32(eocd + 16, true); // central dir offset

  for (let e = 0; e < entries && p + 46 <= bytes.length; e++) {
    if (view.getUint32(p, true) !== 0x02014b50) break;
    const method = view.getUint16(p + 10, true);
    const compSize = view.getUint32(p + 20, true);
    const nameLen = view.getUint16(p + 28, true);
    const extraLen = view.getUint16(p + 30, true);
    const commentLen = view.getUint16(p + 32, true);
    const localOff = view.getUint32(p + 42, true);
    const name = new TextDecoder().decode(bytes.subarray(p + 46, p + 46 + nameLen));

    if (name === "word/document.xml") {
      // jump to local header to find the real data offset
      const lnameLen = view.getUint16(localOff + 26, true);
      const lextraLen = view.getUint16(localOff + 28, true);
      const dataStart = localOff + 30 + lnameLen + lextraLen;
      const compData = bytes.subarray(dataStart, dataStart + compSize);
      const xmlBytes =
        method === 0 ? compData : await inflate(compData, "deflate-raw");
      const xml = new TextDecoder("utf-8").decode(xmlBytes);
      return docxXmlToText(xml);
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  return "";
}

function docxXmlToText(xml: string): string {
  return xml
    .replace(/<w:p\b[^>]*>/g, "\n") // paragraphs → newlines
    .replace(/<w:tab\b[^>]*\/>/g, "\t")
    .replace(/<w:br\b[^>]*\/>/g, "\n")
    .replace(/<[^>]+>/g, "") // strip remaining tags
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/* -------------------------------- PDF ------------------------------------ */

/** Best-effort PDF text extraction. Layer 1 works regardless; this feeds
 *  Layers 2/3 when the PDF's text streams are recoverable. */
async function extractPdfText(bytes: Uint8Array): Promise<string> {
  const latin1 = new TextDecoder("latin1").decode(bytes);
  let collected = "";

  const streamRe = /stream\r?\n/g;
  let m: RegExpExecArray | null;
  while ((m = streamRe.exec(latin1)) !== null) {
    const dataStart = m.index + m[0].length;
    const endIdx = latin1.indexOf("endstream", dataStart);
    if (endIdx < 0) continue;
    const dictStart = Math.max(0, m.index - 300);
    const dict = latin1.slice(dictStart, m.index);
    const chunk = latin1.slice(dataStart, endIdx);

    let streamText = chunk;
    if (/\/FlateDecode/.test(dict)) {
      try {
        const raw = new Uint8Array(chunk.length);
        for (let i = 0; i < chunk.length; i++) raw[i] = chunk.charCodeAt(i) & 0xff;
        const out = await inflate(raw, "deflate");
        streamText = new TextDecoder("latin1").decode(out);
      } catch {
        continue; // not an inflatable content stream (image etc.)
      }
    }
    collected += extractTextOperators(streamText) + "\n";
    if (collected.length > 200_000) break;
  }
  return collected.replace(/\n{3,}/g, "\n\n").trim();
}

/** Pull visible strings out of PDF content-stream text operators (Tj / TJ). */
function extractTextOperators(content: string): string {
  let out = "";
  // ( ... ) Tj   and   [ (..) n (..) ] TJ
  const re = /\((?:[^()\\]|\\.)*\)/g;
  // only harvest parenthesised strings that sit near a text-showing operator
  const tjBlocks = content.match(/(?:\[[^\]]*\]\s*TJ)|(?:\((?:[^()\\]|\\.)*\)\s*Tj)/g);
  if (!tjBlocks) return "";
  for (const block of tjBlocks) {
    let s: RegExpExecArray | null;
    re.lastIndex = 0;
    while ((s = re.exec(block)) !== null) {
      out += s[0]
        .slice(1, -1)
        .replace(/\\([()\\])/g, "$1")
        .replace(/\\n/g, " ")
        .replace(/\\r/g, "")
        .replace(/\\t/g, " ");
    }
    out += " ";
  }
  return out;
}

export const EXPORT_FOR_TESTS = { docxXmlToText, extractTextOperators };
export type { FileType };
