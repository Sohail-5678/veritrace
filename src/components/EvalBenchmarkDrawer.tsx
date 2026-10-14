"use client";

import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { X, FlaskConical, Check, Ban, Loader2, Play } from "lucide-react";
import { runBenchmark, type BenchmarkResult } from "@/lib/evals/benchmark-suite";

interface Props {
  open: boolean;
  onClose: () => void;
}

export function EvalBenchmarkDrawer({ open, onClose }: Props) {
  const [result, setResult] = useState<BenchmarkResult | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    if (open) window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  function run() {
    setBusy(true);
    // allow the spinner to paint before the synchronous crunch
    setTimeout(() => {
      setResult(runBenchmark());
      setBusy(false);
    }, 40);
  }

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-50 flex justify-end"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          style={{ background: "rgba(3,5,9,0.6)", backdropFilter: "blur(5px)" }}
          onClick={onClose}
        >
          <motion.div
            className="glass-strong h-full w-full max-w-md overflow-auto p-6 rounded-l-2xl rounded-r-none"
            initial={{ x: 60 }}
            animate={{ x: 0 }}
            exit={{ x: 60 }}
            transition={{ type: "spring", stiffness: 300, damping: 32 }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center gap-2.5 mb-4">
              <div
                className="grid place-items-center w-9 h-9 rounded-xl"
                style={{ background: "#06B6D422", color: "#22d3ee" }}
              >
                <FlaskConical size={18} />
              </div>
              <div>
                <h3 className="text-base font-semibold tracking-tight">
                  30-Case Eval & Red-Team
                </h3>
                <p className="text-xs text-muted">Statistical + security benchmark</p>
              </div>
              <button onClick={onClose} className="ml-auto btn btn-ghost !p-2" aria-label="Close">
                <X size={16} />
              </button>
            </div>

            <button onClick={run} disabled={busy} className="btn btn-primary w-full">
              {busy ? <Loader2 size={16} className="animate-spin" /> : <Play size={15} />}
              {result ? "Re-run benchmark" : "Run benchmark"}
            </button>

            {result && (
              <div className="mt-5 space-y-4">
                <Section title="Watermark detection">
                  <Stat k="ROC-AUC" v={result.watermark.rocAuc.toFixed(3)} good={result.watermark.rocAuc > 0.9} />
                  <Stat k="TPR @ 1% FPR" v={result.watermark.tprAt1Fpr.toFixed(3)} good={result.watermark.tprAt1Fpr > 0.8} />
                  <Stat k="mean z (watermarked)" v={result.watermark.meanZPos.toFixed(2)} />
                  <Stat k="mean z (human)" v={result.watermark.meanZNeg.toFixed(2)} />
                </Section>

                <Section title="Neutralization (simulated)">
                  <Stat k="Δz (paired)" v={result.neutralization.deltaZ.toFixed(2)} />
                  <Stat k="McNemar χ²" v={result.neutralization.mcnemarChi2.toFixed(2)} />
                  <Stat k="McNemar p" v={String(result.neutralization.mcnemarP)} />
                  <Stat
                    k="detected before → after"
                    v={`${result.neutralization.detectedBefore} → ${result.neutralization.detectedAfter}`}
                  />
                </Section>

                <Section title="Entity-lock fidelity">
                  <Stat
                    k="fidelity"
                    v={`${result.entityLock.fidelity}%`}
                    good={result.entityLock.fidelity >= 100}
                  />
                  <Stat k="entities locked" v={String(result.entityLock.totalLocks)} />
                </Section>

                <Section title="Red-team block rate">
                  <Stat
                    k="block rate"
                    v={`${result.redTeam.blockRate}%`}
                    good={result.redTeam.blockRate >= 100}
                  />
                  <div className="mt-2 space-y-1">
                    {result.redTeam.cases.map((c, i) => (
                      <div
                        key={i}
                        className="flex items-center gap-2 text-[0.72rem] py-1 border-b border-white/5 last:border-0"
                      >
                        {c.blocked ? (
                          <Check size={13} className="text-[#34d399]" />
                        ) : (
                          <Ban size={13} className="text-[#fda4af]" />
                        )}
                        <span className="text-secondary">{c.name}</span>
                        <span className="ml-auto chip mono text-[0.6rem] text-muted">
                          {c.kind}
                        </span>
                      </div>
                    ))}
                  </div>
                </Section>

                <p className="text-[0.64rem] text-muted mono text-center">
                  completed in {result.elapsedMs} ms · deterministic · synthetic corpus
                </p>
              </div>
            )}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="glass p-4">
      <h4 className="text-xs font-semibold text-secondary mb-2.5 tracking-tight">
        {title}
      </h4>
      <div className="space-y-1.5">{children}</div>
    </div>
  );
}

function Stat({ k, v, good }: { k: string; v: string; good?: boolean }) {
  return (
    <div className="flex justify-between items-baseline text-xs">
      <span className="text-muted">{k}</span>
      <span
        className="mono font-semibold"
        style={{ color: good === undefined ? "var(--text-primary)" : good ? "#34d399" : "#fcd34d" }}
      >
        {v}
      </span>
    </div>
  );
}
