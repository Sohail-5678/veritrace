"use client";

import { useState } from "react";
import {
  Sparkles,
  ShieldCheck,
  Download,
  Wand2,
  ArrowRight,
  Info,
  Loader2,
} from "lucide-react";
import type { Layer4Result } from "@/lib/forensics/types";
import { sanitizeLocal, buildCleanPdf } from "@/lib/forensics/layer4-sanitizer";

interface Props {
  text: string;
  title?: string;
  simulateBefore?: boolean;
  onSanitized?: (done: boolean) => void;
}

export function SurgicalDiffMatrix({
  text,
  title = "Sanitized Document",
  simulateBefore = false,
  onSanitized,
}: Props) {
  const [result, setResult] = useState<Layer4Result | null>(null);
  const [engine, setEngine] = useState<"local" | "groq">("local");
  const [apiKey, setApiKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [pdfBusy, setPdfBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setNote(null);
    try {
      if (engine === "groq") {
        const resp = await fetch("/api/sanitize", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ text, engine: "groq", apiKey: apiKey || undefined }),
        });
        const data = await resp.json();
        if (!resp.ok) {
          setNote(data?.error ?? "Sanitize failed.");
        } else {
          setResult(data.result);
          if (data.groqNote) setNote(data.groqNote);
          onSanitized?.(true);
        }
      } else {
        // instant, offline, client-side
        const r = sanitizeLocal(text, { simulateWatermarkBefore: simulateBefore });
        setResult(r);
        onSanitized?.(true);
      }
    } catch (e) {
      setNote("Sanitize failed: " + (e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function downloadPdf() {
    if (!result) return;
    setPdfBusy(true);
    try {
      const bytes = await buildCleanPdf(result.sanitized, { title });
      const blob = new Blob([bytes as BlobPart], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `veritrace-clean-${Date.now()}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setPdfBusy(false);
    }
  }

  return (
    <div className="glass p-6">
      <div className="flex items-center gap-2.5">
        <div
          className="grid place-items-center w-9 h-9 rounded-xl"
          style={{ background: "#10B98122", color: "#34d399" }}
        >
          <Sparkles size={18} />
        </div>
        <div>
          <h3 className="text-base font-semibold tracking-tight">
            Layer 4 · Entity-Locked Sanitizer
          </h3>
          <p className="text-xs text-muted">
            Document hygiene: strip hidden channels · normalize · entity-lock
          </p>
        </div>
      </div>

      {!result ? (
        <div className="mt-5">
          <div className="flex flex-col sm:flex-row gap-3 sm:items-end">
            <div>
              <label className="text-[0.7rem] text-secondary block mb-1.5">
                Rewrite engine
              </label>
              <div className="flex p-1 rounded-xl bg-white/5 border border-white/5 w-max">
                {(["local", "groq"] as const).map((e) => (
                  <button
                    key={e}
                    onClick={() => setEngine(e)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                      engine === e
                        ? "bg-[var(--clean)] text-[#04131a]"
                        : "text-secondary hover:text-primary"
                    }`}
                  >
                    {e === "local" ? "Local (instant, $0)" : "Groq BYOK (optional)"}
                  </button>
                ))}
              </div>
            </div>
            {engine === "groq" && (
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="gsk_… (never stored)"
                className="mono text-xs px-3 py-2 rounded-lg bg-black/30 border border-white/10 focus:border-[var(--analytic)] outline-none flex-1"
              />
            )}
          </div>

          <button
            onClick={run}
            disabled={busy}
            className="btn btn-primary mt-4 disabled:opacity-60"
          >
            {busy ? <Loader2 size={16} className="animate-spin" /> : <Wand2 size={16} />}
            Run Surgical Sanitization
          </button>
          {note && <p className="text-xs text-[#fcd34d] mt-3">{note}</p>}

          <ResponsibleNote />
        </div>
      ) : (
        <div className="mt-5">
          {/* integrity badge + metrics */}
          <div className="flex flex-wrap items-center gap-2 mb-4">
            <span
              className="chip font-semibold"
              style={{
                borderColor: "#10B98166",
                color: "#34d399",
                background: "rgba(16,185,129,0.1)",
              }}
            >
              <ShieldCheck size={13} /> Entity Lock{" "}
              {(result.entityRecall * 100).toFixed(1)}%
            </span>
            <span className="chip mono text-secondary">
              {result.locks.length} entities locked
            </span>
            <span className="chip mono text-secondary">
              {result.removedCodepoints} invisible removed
            </span>
            <span className="chip mono text-secondary">
              {result.stylisticEdits.length} style edits
            </span>
            <span className="chip mono text-muted">engine: {result.engine}</span>
          </div>

          {/* before → after metrics */}
          <div className="grid grid-cols-3 gap-2 mb-4">
            <MetricDelta
              label="z-score"
              before={result.before.zScore.toFixed(2)}
              after={result.after.zScore.toFixed(2)}
            />
            <MetricDelta
              label="mean g"
              before={result.before.meanG.toFixed(3)}
              after={result.after.meanG.toFixed(3)}
            />
            <MetricDelta
              label="anomalies"
              before={String(result.before.anomalyCount)}
              after={String(result.after.anomalyCount)}
            />
          </div>

          {/* side-by-side */}
          <div className="grid md:grid-cols-2 gap-3">
            <DocColumn title="Original" tone="#fda4af" text={result.original} />
            <DocColumn title="Sanitized" tone="#34d399" text={result.sanitized} />
          </div>

          {/* edits */}
          {result.stylisticEdits.length > 0 && (
            <div className="mt-4">
              <h4 className="text-xs font-semibold text-secondary mb-2">
                Stylistic edits
              </h4>
              <div className="space-y-1.5 max-h-40 overflow-auto">
                {result.stylisticEdits.map((e, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-2 text-[0.72rem] mono p-2 rounded-lg bg-white/[0.03]"
                  >
                    <span className="text-[#fda4af] line-through">{e.from}</span>
                    <ArrowRight size={12} className="text-muted shrink-0" />
                    <span className="text-[#34d399]">{e.to}</span>
                    <span className="ml-auto text-muted text-[0.64rem]">{e.reason}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* notes */}
          <ul className="mt-4 space-y-1 text-[0.72rem] text-muted">
            {result.notes.map((n, i) => (
              <li key={i} className="flex gap-1.5">
                <span className="text-[var(--clean)]">›</span>
                {n}
              </li>
            ))}
          </ul>

          <div className="flex flex-wrap gap-2 mt-5">
            <button onClick={downloadPdf} disabled={pdfBusy} className="btn btn-primary">
              {pdfBusy ? (
                <Loader2 size={16} className="animate-spin" />
              ) : (
                <Download size={16} />
              )}
              Download clean PDF
            </button>
            <button
              onClick={() => {
                navigator.clipboard?.writeText(result.sanitized);
              }}
              className="btn btn-ghost"
            >
              Copy sanitized text
            </button>
            <button onClick={() => setResult(null)} className="btn btn-ghost">
              Reset
            </button>
          </div>
          {note && <p className="text-xs text-[#fcd34d] mt-3">{note}</p>}
          <ResponsibleNote />
        </div>
      )}
    </div>
  );
}

function MetricDelta({
  label,
  before,
  after,
}: {
  label: string;
  before: string;
  after: string;
}) {
  return (
    <div className="p-2.5 rounded-xl bg-white/[0.03] border border-white/5 text-center">
      <div className="text-[0.64rem] text-muted mb-1">{label}</div>
      <div className="flex items-center justify-center gap-1.5 mono text-xs">
        <span className="text-[#fda4af]">{before}</span>
        <ArrowRight size={11} className="text-muted" />
        <span className="text-[#34d399]">{after}</span>
      </div>
    </div>
  );
}

function DocColumn({ title, tone, text }: { title: string; tone: string; text: string }) {
  return (
    <div>
      <div className="text-[0.7rem] font-semibold mb-1.5" style={{ color: tone }}>
        {title}
      </div>
      <div className="mono text-[0.72rem] leading-6 p-3 rounded-xl bg-black/30 border border-white/5 h-56 overflow-auto whitespace-pre-wrap text-secondary">
        {text}
      </div>
    </div>
  );
}

function ResponsibleNote() {
  return (
    <div className="mt-4 flex gap-2 text-[0.68rem] text-muted p-3 rounded-xl bg-white/[0.02] border border-white/5">
      <Info size={13} className="shrink-0 mt-0.5 text-[var(--analytic)]" />
      <span>
        Responsible use: this tool removes hidden prompt-injections, tracking
        canaries and typographic noise, and polishes writing style. It is for
        document hygiene and privacy — not for misrepresenting the authorship or
        provenance of generated content.
      </span>
    </div>
  );
}
