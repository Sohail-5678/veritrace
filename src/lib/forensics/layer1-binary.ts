/**
 * Layer 1 — Binary, Font-Subset & C2PA Container Forensics
 * -----------------------------------------------------------------------------
 * Operates on the RAW bytes of an uploaded document (no text extraction needed)
 * and surfaces the provenance fingerprints that cloud / headless-container
 * renderers leave behind:
 *   - /Producer, /Creator, /Author, /Title and XMP packet signatures
 *   - C2PA / JUMBF "Content Credentials" manifests
 *   - Container font subsets (DejaVuSans, Liberation, Nimbus, Droid ...)
 *   - Active-content keys that make a PDF dangerous (/JS, /OpenAction, /Launch)
 *
 * It is fully deterministic and runs in a few milliseconds on both the browser
 * and the Edge runtime. Nothing is written to disk.
 */

import type {
  FileType,
  FontFinding,
  Layer1Finding,
  Layer1Result,
} from "./types";

/** Known AI / headless-container producer & creator fingerprints. */
const CONTAINER_PRODUCERS: { pattern: RegExp; label: string; note: string }[] =
  [
    {
      pattern: /Skia\/PDF/i,
      label: "Skia/PDF",
      note: "Chromium/Google Docs headless renderer — common in cloud AI sandboxes.",
    },
    {
      pattern: /WeasyPrint/i,
      label: "WeasyPrint",
      note: "Python HTML→PDF engine used by server-side document generators.",
    },
    {
      pattern: /ReportLab/i,
      label: "ReportLab PDF Library",
      note: "Python PDF toolkit frequently used by automated pipelines.",
    },
    {
      pattern: /Cairo/i,
      label: "Cairo",
      note: "Linux graphics library backing many headless PDF exports.",
    },
    {
      pattern: /Chromium|HeadlessChrome/i,
      label: "Chromium",
      note: "Headless Chromium print-to-PDF — hallmark of a sandboxed render.",
    },
    {
      pattern: /LibreOffice/i,
      label: "LibreOffice",
      note: "Headless LibreOffice conversion, typical of server containers.",
    },
    {
      pattern: /python-docx/i,
      label: "python-docx",
      note: "Programmatic DOCX authoring library.",
    },
    {
      pattern: /Pandoc/i,
      label: "Pandoc",
      note: "Automated document converter.",
    },
    {
      pattern: /wkhtmltopdf/i,
      label: "wkhtmltopdf",
      note: "Qt WebKit HTML→PDF converter used in CI pipelines.",
    },
  ];

/** Desktop producers that read as "human authored on a real workstation". */
const DESKTOP_PRODUCERS: RegExp[] = [
  /Quartz PDFContext/i,
  /Mac OS X/i,
  /macOS/i,
  /Microsoft.*Word/i,
  /Acrobat/i,
  /PScript5/i,
  /Preview/i,
];

/** Container / headless default font subsets. */
const CONTAINER_FONTS: RegExp[] = [
  /DejaVu/i,
  /Liberation/i,
  /Nimbus/i,
  /Droid/i,
  /Noto(?!Color)/i,
  /FreeSans|FreeSerif/i,
  /Carlito|Caladea/i,
];

/** PDF keys that make a document actively dangerous. */
const ACTIVE_CONTENT_KEYS: { key: string; note: string }[] = [
  { key: "/JavaScript", note: "Embedded document JavaScript." },
  { key: "/JS", note: "JavaScript action stream." },
  { key: "/OpenAction", note: "Code that runs automatically when opened." },
  { key: "/AA", note: "Additional (event-triggered) actions." },
  { key: "/Launch", note: "Launches an external application / file." },
  { key: "/RichMedia", note: "Embedded Flash / rich-media payload." },
  { key: "/EmbeddedFile", note: "File embedded inside the PDF container." },
  { key: "/XFA", note: "XFA forms — a historic exploit surface." },
];

/** C2PA / JUMBF content-credential markers. */
const C2PA_MARKERS: string[] = [
  "jumb",
  "c2pa",
  "c2ma",
  "c2cl",
  "urn:uuid:",
  "contentauth",
  "cai\u0000",
];

export function detectFileType(bytes: Uint8Array): FileType {
  // %PDF-
  if (
    bytes.length >= 5 &&
    bytes[0] === 0x25 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x44 &&
    bytes[3] === 0x46 &&
    bytes[4] === 0x2d
  ) {
    return "pdf";
  }
  // PK\x03\x04 (ZIP container → DOCX/XLSX/PPTX)
  if (
    bytes.length >= 4 &&
    bytes[0] === 0x50 &&
    bytes[1] === 0x4b &&
    bytes[2] === 0x03 &&
    bytes[3] === 0x04
  ) {
    return "docx";
  }
  return "text";
}

/** Decode bytes 1:1 into a latin1 string so regex can scan the binary. */
function toLatin1(bytes: Uint8Array): string {
  try {
    return new TextDecoder("latin1").decode(bytes);
  } catch {
    let out = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      out += String.fromCharCode.apply(
        null,
        Array.from(bytes.subarray(i, i + chunk)),
      );
    }
    return out;
  }
}

/** Extract a PDF info-dictionary string value (literal `( )` or hex `< >`). */
function extractInfoValue(raw: string, key: string): string | null {
  // literal string
  const litRe = new RegExp(
    `\\/${key}\\s*\\(((?:[^()\\\\]|\\\\.)*)\\)`,
    "i",
  );
  const lit = litRe.exec(raw);
  if (lit && lit[1]) {
    return lit[1]
      .replace(/\\([()\\])/g, "$1")
      .replace(/\\n/g, " ")
      .replace(/\\r/g, " ")
      .trim();
  }
  // hex string
  const hexRe = new RegExp(`\\/${key}\\s*<([0-9A-Fa-f\\s]+)>`, "i");
  const hex = hexRe.exec(raw);
  if (hex && hex[1]) {
    const clean = hex[1].replace(/\s+/g, "");
    let s = "";
    for (let i = 0; i + 1 < clean.length; i += 2) {
      s += String.fromCharCode(parseInt(clean.slice(i, i + 2), 16));
    }
    // strip UTF-16 BOM + nulls that Acrobat likes to add
    return s.replace(/^﻿/, "").replace(/\u0000/g, "").trim();
  }
  return null;
}

function classifyProducer(value: string): {
  severity: "clean" | "caution" | "threat";
  note: string;
} {
  for (const c of CONTAINER_PRODUCERS) {
    if (c.pattern.test(value)) {
      return { severity: "threat", note: c.note };
    }
  }
  for (const d of DESKTOP_PRODUCERS) {
    if (d.test(value)) {
      return {
        severity: "clean",
        note: "Consistent with a genuine desktop application.",
      };
    }
  }
  return {
    severity: "caution",
    note: "Unrecognised producer — review manually.",
  };
}

export function inspectBinary(
  bytes: Uint8Array,
  fileName = "",
): Layer1Result {
  const fileType = detectFileType(bytes);
  const findings: Layer1Finding[] = [];
  const fonts: FontFinding[] = [];
  const activeContentKeys: string[] = [];
  let c2paDetected = false;
  let risk = 0;

  if (fileType !== "pdf" && fileType !== "docx") {
    return {
      applicable: false,
      fileType,
      byteLength: bytes.length,
      findings: [],
      fonts: [],
      activeContentKeys: [],
      c2paDetected: false,
      containerRiskScore: 0,
      summary:
        "Plain text input — no binary container to inspect. Layers 2 & 3 carry the analysis.",
    };
  }

  const raw = toLatin1(bytes);

  // ---- Info dictionary fingerprints -------------------------------------
  for (const key of ["Producer", "Creator", "Author", "Title"] as const) {
    const value = extractInfoValue(raw, key);
    if (!value) continue;
    if (key === "Producer" || key === "Creator") {
      const { severity, note } = classifyProducer(value);
      if (severity === "threat") risk += 34;
      else if (severity === "caution") risk += 8;
      findings.push({
        key: `/${key}`,
        value,
        category: key.toLowerCase() as "producer" | "creator",
        severity,
        explanation: note,
      });
    } else {
      findings.push({
        key: `/${key}`,
        value,
        category: key === "Author" ? "author" : "title",
        severity: "clean",
        explanation: "Descriptive metadata.",
      });
    }
  }

  // ---- XMP packet -------------------------------------------------------
  const xmp = /<x:xmpmeta[\s\S]{0,8000}?<\/x:xmpmeta>/i.exec(raw);
  if (xmp) {
    const tool =
      /<xmp:CreatorTool>([^<]+)<\/xmp:CreatorTool>/i.exec(xmp[0])?.[1] ??
      /<pdf:Producer>([^<]+)<\/pdf:Producer>/i.exec(xmp[0])?.[1] ??
      "present";
    const { severity, note } = classifyProducer(tool);
    if (severity === "threat") risk += 14;
    findings.push({
      key: "XMP <x:xmpmeta>",
      value: tool.length > 120 ? tool.slice(0, 120) + "…" : tool,
      category: "xmp",
      severity,
      explanation:
        "Adobe XMP metadata packet embedded in the document — " + note,
    });
  }

  // ---- C2PA / JUMBF -----------------------------------------------------
  const lowerRaw = raw.toLowerCase();
  for (const marker of C2PA_MARKERS) {
    if (lowerRaw.includes(marker)) {
      c2paDetected = true;
      break;
    }
  }
  if (c2paDetected) {
    risk += 22;
    findings.push({
      key: "C2PA / JUMBF manifest",
      value: "Content Credentials box detected",
      category: "c2pa",
      severity: "caution",
      explanation:
        "An embedded C2PA/JUMBF provenance manifest was found. Useful for attribution, but it also reveals the generating tool-chain.",
    });
  }

  // ---- Fonts ------------------------------------------------------------
  const seenFonts = new Set<string>();
  const fontRe = /\/BaseFont\s*\/([A-Za-z0-9+\-,.]+)/g;
  let fm: RegExpExecArray | null;
  while ((fm = fontRe.exec(raw)) !== null) {
    let name = fm[1];
    // subset prefix like "ABCDEF+DejaVuSans"
    const plus = name.indexOf("+");
    if (plus === 6) name = name.slice(7);
    if (seenFonts.has(name)) continue;
    seenFonts.add(name);
    const container = CONTAINER_FONTS.some((re) => re.test(name));
    fonts.push({
      name,
      container,
      note: container
        ? "Default font of a headless Linux container — not installed on typical desktops."
        : "Standard / desktop font.",
    });
    if (container) risk += 10;
  }

  // ---- Active content ---------------------------------------------------
  for (const { key, note } of ACTIVE_CONTENT_KEYS) {
    if (raw.includes(key)) {
      activeContentKeys.push(key);
      const heavy = key === "/Launch" || key === "/JavaScript" || key === "/JS";
      risk += heavy ? 20 : 10;
      findings.push({
        key,
        value: "present",
        category: "active-content",
        severity: heavy ? "threat" : "caution",
        explanation:
          note +
          " Layer 4 rebuilds the document from clean text, which removes this entirely.",
      });
    }
  }

  if (fileName) {
    findings.unshift({
      key: "filename",
      value: fileName,
      category: "info",
      severity: "clean",
      explanation: "Original upload name (never written to disk).",
    });
  }

  const containerRiskScore = Math.max(0, Math.min(100, Math.round(risk)));

  const summary =
    containerRiskScore >= 60
      ? "High container-provenance risk: strong headless/AI render fingerprints present."
      : containerRiskScore >= 25
        ? "Moderate provenance footprint — some generator metadata detected."
        : "Low provenance footprint.";

  return {
    applicable: true,
    fileType,
    byteLength: bytes.length,
    findings,
    fonts,
    activeContentKeys,
    c2paDetected,
    containerRiskScore,
    summary,
  };
}
