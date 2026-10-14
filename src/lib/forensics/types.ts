/**
 * Shared forensic types used across all four layers, the API routes, the demo
 * artifacts and the UI. Everything here is plain data (JSON-serialisable) so it
 * can cross the client/server boundary unchanged.
 */

export type Severity = "clean" | "caution" | "threat";
export type FileType = "pdf" | "docx" | "text" | "unknown";

/* ----------------------------- Layer 1 ----------------------------------- */

export type Layer1Category =
  | "producer"
  | "creator"
  | "author"
  | "title"
  | "xmp"
  | "c2pa"
  | "font"
  | "active-content"
  | "info";

export interface Layer1Finding {
  key: string;
  value: string;
  category: Layer1Category;
  severity: Severity;
  explanation: string;
}

export interface FontFinding {
  name: string;
  container: boolean;
  note: string;
}

export interface Layer1Result {
  applicable: boolean;
  fileType: FileType;
  byteLength: number;
  findings: Layer1Finding[];
  fonts: FontFinding[];
  activeContentKeys: string[];
  c2paDetected: boolean;
  containerRiskScore: number; // 0..100
  summary: string;
}

/* ----------------------------- Layer 2 ----------------------------------- */

export type UnicodeCategory =
  | "zero-width"
  | "tag"
  | "variation-selector"
  | "nbsp"
  | "narrow-nbsp"
  | "soft-hyphen"
  | "bom"
  | "homoglyph"
  | "em-dash";

export interface UnicodeFinding {
  codepoint: number;
  label: string; // "U+202F"
  name: string;
  category: UnicodeCategory;
  severity: Severity;
  count: number;
  positions: number[]; // char offsets (first N sampled)
  note: string;
}

export interface HomoglyphHit {
  word: string;
  normalized: string;
  index: number;
  script: string;
}

export interface Layer2Result {
  findings: UnicodeFinding[];
  totalAnomalies: number;
  threatCount: number; // count of threat-severity findings
  decodedHiddenMessage: string | null; // reconstructed from tag chars
  homoglyphHits: HomoglyphHit[];
  emDashDensityPer500: number;
}

/* ----------------------------- Layer 3 ----------------------------------- */

export type LockState = "LOCKED" | "MUTABLE";

export interface Token {
  text: string;
  index: number;
  start: number;
  end: number;
  isWord: boolean;
  entropy: number; // bits, 0..5
  lock: LockState;
  lockReason: string | null;
  green: boolean;
  gScore: number; // 0..1 mean tournament g
}

export type WatermarkVerdict =
  | "likely-watermarked"
  | "inconclusive"
  | "likely-human";

export interface Layer3Result {
  tokens: Token[];
  wordCount: number;
  zScore: number;
  pValue: number;
  meanG: number;
  greenFraction: number;
  lockedCount: number;
  carrierCount: number;
  verdict: WatermarkVerdict;
  seed: number;
}

/* ----------------------------- Layer 4 ----------------------------------- */

export type EntityType =
  | "metric"
  | "percent"
  | "currency"
  | "date"
  | "url"
  | "email"
  | "phone"
  | "tech"
  | "proper-noun";

export interface EntityLock {
  value: string;
  type: EntityType;
  index: number;
}

export interface StylisticEdit {
  from: string;
  to: string;
  reason: string;
}

export interface ForensicSnapshot {
  zScore: number;
  pValue: number;
  meanG: number;
  anomalyCount: number;
}

export type SanitizerEngine = "local-deterministic" | "groq-byok";

export interface Layer4Result {
  original: string;
  sanitized: string;
  locks: EntityLock[];
  entityRecall: number; // 0..1 (gate requires 1)
  missingLocks: string[];
  removedCodepoints: number;
  stylisticEdits: StylisticEdit[];
  before: ForensicSnapshot;
  after: ForensicSnapshot;
  engine: SanitizerEngine;
  passedGate: boolean;
  notes: string[];
}

/* --------------------------- Combined scan ------------------------------- */

export interface ScanResult {
  fileType: FileType;
  byteLength: number;
  textLength: number;
  layer1: Layer1Result;
  layer2: Layer2Result;
  layer3: Layer3Result;
  elapsedMs: number;
}
