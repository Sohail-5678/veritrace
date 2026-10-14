"use client";

import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { motion } from "framer-motion";
import {
  FileUser,
  ShieldAlert,
  Bug,
  Upload,
  ScanSearch,
  Sparkles,
  ArrowUp,
  Lock,
  FileText,
} from "lucide-react";
import { Navbar } from "@/components/Navbar";
import { ForensicTelemetryHUD } from "@/components/ForensicTelemetryHUD";
import { SpatialLayerStack } from "@/components/SpatialLayerStack";
import { BinaryForensicsPanel } from "@/components/BinaryForensicsPanel";
import { UnicodeStegoPanel } from "@/components/UnicodeStegoPanel";
import { EntropyHeatmapViewer } from "@/components/EntropyHeatmapViewer";
import { SurgicalDiffMatrix } from "@/components/SurgicalDiffMatrix";
import { SecurityGuardrailModal } from "@/components/SecurityGuardrailModal";
import { EvalBenchmarkDrawer } from "@/components/EvalBenchmarkDrawer";
import {
  DEMO_ARTIFACTS,
  analyzeDemo,
  getDemoById,
} from "@/lib/demo-artifacts";
import { analyzeText, analyzeBytes } from "@/lib/forensics/analyze";
import { validateText, validateUpload, MAX_TEXT_CHARS } from "@/lib/security/input-firewall";
import type { ScanResult } from "@/lib/forensics/types";

const DEMO_ICONS: Record<string, typeof FileUser> = {
  resume: FileUser,
  memo: ShieldAlert,
  invoice: Bug,
};

type Mode = "demo" | "live";

export default function Home() {
  const [mode, setMode] = useState<Mode>("demo");
  const [demoId, setDemoId] = useState("resume");
  const [liveText, setLiveText] = useState("");
  const [liveScan, setLiveScan] = useState<(ScanResult & { extractedText?: string }) | null>(null);
  const [sanitized, setSanitized] = useState(false);
  const [securityOpen, setSecurityOpen] = useState(false);
  const [benchmarkOpen, setBenchmarkOpen] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [highlight, setHighlight] = useState<number | null>(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => setMounted(true), []);

  const panelRefs = useRef<(HTMLDivElement | null)[]>([]);

  const demo = getDemoById(demoId);
  const demoScan = useMemo(() => analyzeDemo(demo), [demo]);

  const activeScan: ScanResult | null = mode === "demo" ? demoScan : liveScan;
  const activeText = mode === "demo" ? demo.text : liveText;
  const simulateBefore = mode === "demo" ? demo.simulateWatermark : false;
  const sanitizeTitle = mode === "demo" ? demo.title : "Sanitized Document";

  const focusLayer = useCallback((i: number) => {
    panelRefs.current[i]?.scrollIntoView({ behavior: "smooth", block: "center" });
    setHighlight(i);
    window.setTimeout(() => setHighlight(null), 1600);
  }, []);

  function selectDemo(id: string) {
    setDemoId(id);
    setSanitized(false);
  }

  function runText() {
    setErr(null);
    setNotice(null);
    const v = validateText(liveText);
    if (!v.ok) {
      setErr(v.reason ?? "Invalid input.");
      return;
    }
    setLiveScan(analyzeText(liveText));
    setSanitized(false);
  }

  const handleFile = useCallback(async (file: File) => {
    setErr(null);
    setNotice(null);
    try {
      const buf = new Uint8Array(await file.arrayBuffer());
      const fw = validateUpload(buf);
      if (!fw.ok) {
        setErr(fw.reason ?? "File rejected by firewall.");
        return;
      }
      setLoading(true);
      const res = await analyzeBytes(buf, file.name);
      setLiveScan(res);
      setLiveText(res.extractedText ?? "");
      setSanitized(false);
      if ((res.textLength ?? 0) < 20 && res.fileType === "pdf") {
        setNotice(
          "This PDF's text streams weren't recoverable in-browser — Layer 1 (binary/container) is fully shown above. For deep Layer 2 & 3 analysis, paste the text below.",
        );
      }
    } catch (e) {
      setErr("Could not read file: " + (e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  return (
    <div className="min-h-screen pb-24">
      <Navbar
        onOpenSecurity={() => setSecurityOpen(true)}
        onOpenBenchmark={() => setBenchmarkOpen(true)}
      />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 mt-8">
        {/* ---------------------------------------------------------------- */}
        {/* HERO                                                              */}
        {/* ---------------------------------------------------------------- */}
        <section className="text-center max-w-3xl mx-auto fade-up">
          <span className="chip text-muted mb-4">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--clean)] animate-pulse" />
            Four-layer zero-trust document forensics
          </span>
          <h1 className="text-4xl sm:text-5xl font-bold tracking-tightest leading-[1.05]">
            Trace the <span className="text-grad">provenance</span> of any document
          </h1>
          <p className="text-secondary mt-4 text-[0.95rem] leading-relaxed">
            Binary & C2PA container forensics, Unicode steganography and
            prompt-injection detection, SynthID / Kirchenbauer entropy
            visualization, and entity-locked sanitization — all local-first, at
            $0, with your files never leaving the browser.
          </p>
        </section>

        {/* mode toggle */}
        <div className="flex justify-center mt-8">
          <div className="flex p-1 rounded-2xl glass">
            <ModeBtn active={mode === "demo"} onClick={() => setMode("demo")} icon={<ScanSearch size={15} />}>
              Demo Sandbox
            </ModeBtn>
            <ModeBtn active={mode === "live"} onClick={() => setMode("live")} icon={<Upload size={15} />}>
              Use Your Own
            </ModeBtn>
          </div>
        </div>

        {/* ---------------------------------------------------------------- */}
        {/* DEMO SELECTOR                                                     */}
        {/* ---------------------------------------------------------------- */}
        {mode === "demo" && (
          <section className="mt-6">
            <div className="grid sm:grid-cols-3 gap-3">
              {DEMO_ARTIFACTS.map((a) => {
                const Icon = DEMO_ICONS[a.id] ?? FileText;
                const active = a.id === demoId;
                return (
                  <button
                    key={a.id}
                    onClick={() => selectDemo(a.id)}
                    className={`glass p-4 text-left transition-all ${
                      active ? "ring-1 ring-[var(--analytic)]" : "opacity-75 hover:opacity-100"
                    }`}
                    style={active ? { boxShadow: "0 0 30px -10px #06B6D4" } : undefined}
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <div
                        className="grid place-items-center w-8 h-8 rounded-lg"
                        style={{ background: "#06B6D422", color: "#22d3ee" }}
                      >
                        <Icon size={15} />
                      </div>
                      <span className="chip text-[0.6rem] text-muted">{a.useCase}</span>
                    </div>
                    <div className="text-sm font-semibold tracking-tight leading-snug">
                      {a.title}
                    </div>
                    <div className="text-[0.7rem] text-muted mt-0.5">{a.subtitle}</div>
                  </button>
                );
              })}
            </div>
            <p className="text-[0.7rem] text-muted mt-3 text-center">
              Pre-loaded forensic artifacts — Layers 2 & 3 run live on genuine
              embedded anomalies; Layer 1 shows representative container metadata.
            </p>
          </section>
        )}

        {/* ---------------------------------------------------------------- */}
        {/* LIVE WORKSPACE                                                    */}
        {/* ---------------------------------------------------------------- */}
        {mode === "live" && (
          <section className="mt-6 grid md:grid-cols-2 gap-4">
            <label
              onDragOver={(e) => {
                e.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragging(false);
                const f = e.dataTransfer.files?.[0];
                if (f) handleFile(f);
              }}
              className={`glass p-6 flex flex-col items-center justify-center text-center cursor-pointer border-dashed transition-all min-h-[200px] ${
                dragging ? "ring-2 ring-[var(--analytic)]" : ""
              }`}
            >
              <input
                type="file"
                accept=".pdf,.docx,.txt,.md,.tex,text/plain"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) handleFile(f);
                }}
              />
              <div
                className="grid place-items-center w-12 h-12 rounded-2xl mb-3"
                style={{ background: "#06B6D422", color: "#22d3ee" }}
              >
                <Upload size={22} />
              </div>
              <div className="font-semibold text-sm">Drop a .pdf / .docx / .txt / .md</div>
              <div className="text-xs text-muted mt-1">
                or click to browse · max 4.5 MB
              </div>
              <div className="chip text-[#6ee7b7] mt-3" style={{ borderColor: "#10B98144" }}>
                <Lock size={11} /> Analyzed in-browser — never uploaded
              </div>
            </label>

            <div className="glass p-5 flex flex-col">
              <label className="text-xs text-secondary mb-2 font-medium">
                …or paste text directly
              </label>
              <textarea
                value={liveText}
                onChange={(e) => setLiveText(e.target.value)}
                placeholder="Paste a resume, memo, email or any text to run Layers 2–4…"
                className="flex-1 min-h-[120px] mono text-xs p-3 rounded-xl bg-black/30 border border-white/10 focus:border-[var(--analytic)] outline-none resize-none"
                maxLength={MAX_TEXT_CHARS}
              />
              <div className="flex items-center justify-between mt-3">
                <span className="text-[0.64rem] text-muted mono">
                  {liveText.length.toLocaleString()} / {MAX_TEXT_CHARS.toLocaleString()}
                </span>
                <button onClick={runText} disabled={loading} className="btn btn-primary">
                  <ScanSearch size={15} /> Run forensic scan
                </button>
              </div>
            </div>
          </section>
        )}

        {(err || notice) && (
          <div className="mt-4 space-y-2">
            {err && (
              <div className="glass p-3 text-sm text-[#fda4af] border-[#F43F5E55]">
                {err}
              </div>
            )}
            {notice && (
              <div className="glass p-3 text-sm text-[#fcd34d]">{notice}</div>
            )}
          </div>
        )}

        {/* ---------------------------------------------------------------- */}
        {/* RESULTS                                                           */}
        {/* ---------------------------------------------------------------- */}
        {mounted && activeScan ? (
          <div className="mt-8 space-y-5">
            <ForensicTelemetryHUD scan={activeScan} />

            <SpatialLayerStack scan={activeScan} onFocus={focusLayer} sanitized={sanitized} />

            <div className="grid lg:grid-cols-2 gap-5">
              <FocusWrap idx={0} highlight={highlight} refs={panelRefs}>
                <BinaryForensicsPanel layer1={activeScan.layer1} />
              </FocusWrap>
              <FocusWrap idx={1} highlight={highlight} refs={panelRefs}>
                <UnicodeStegoPanel layer2={activeScan.layer2} />
              </FocusWrap>
            </div>

            <FocusWrap idx={2} highlight={highlight} refs={panelRefs}>
              <EntropyHeatmapViewer layer3={activeScan.layer3} />
            </FocusWrap>

            <FocusWrap idx={3} highlight={highlight} refs={panelRefs}>
              {activeText && activeText.length > 0 ? (
                <SurgicalDiffMatrix
                  key={mode + demoId + activeText.length}
                  text={activeText}
                  title={sanitizeTitle}
                  simulateBefore={simulateBefore}
                  onSanitized={setSanitized}
                />
              ) : (
                <div className="glass p-6 text-sm text-muted flex items-center gap-2">
                  <Sparkles size={16} className="text-[var(--clean)]" />
                  Add text above to enable Layer 4 sanitization.
                </div>
              )}
            </FocusWrap>
          </div>
        ) : (
          mounted &&
          mode === "live" && (
            <div className="mt-10 text-center text-muted text-sm">
              Drop a file or paste text to begin — or switch to the Demo Sandbox
              to explore instantly.
            </div>
          )
        )}

        {/* footer */}
        <footer className="mt-16 text-center text-[0.72rem] text-muted">
          <div className="flex items-center justify-center gap-3 flex-wrap">
            <span>VeriTrace · zero-trust document forensics</span>
            <span>·</span>
            <span>$0 · local-first · stateless</span>
            <span>·</span>
            <button
              onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
              className="inline-flex items-center gap-1 hover:text-primary transition"
            >
              <ArrowUp size={12} /> back to top
            </button>
          </div>
          <p className="mt-2 max-w-xl mx-auto">
            For document hygiene, privacy and defensive security research. Not for
            misrepresenting the authorship or provenance of generated content.
          </p>
        </footer>
      </main>

      <SecurityGuardrailModal open={securityOpen} onClose={() => setSecurityOpen(false)} />
      <EvalBenchmarkDrawer open={benchmarkOpen} onClose={() => setBenchmarkOpen(false)} />
    </div>
  );
}

function ModeBtn({
  active,
  onClick,
  icon,
  children,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition ${
        active ? "bg-[var(--analytic)] text-[#04131a]" : "text-secondary hover:text-primary"
      }`}
    >
      {icon}
      {children}
    </button>
  );
}

function FocusWrap({
  idx,
  highlight,
  refs,
  children,
}: {
  idx: number;
  highlight: number | null;
  refs: React.MutableRefObject<(HTMLDivElement | null)[]>;
  children: React.ReactNode;
}) {
  return (
    <motion.div
      ref={(el) => {
        refs.current[idx] = el;
      }}
      animate={
        highlight === idx
          ? { boxShadow: "0 0 0 2px #06B6D4, 0 0 40px -6px #06B6D4" }
          : { boxShadow: "0 0 0 0px transparent" }
      }
      transition={{ duration: 0.4 }}
      className="rounded-2xl"
    >
      {children}
    </motion.div>
  );
}
