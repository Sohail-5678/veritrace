"use client";

import { useState } from "react";
import type { Layer3Result, Token } from "@/lib/forensics/types";
import { Activity, Lock, Unlock } from "lucide-react";

type View = "entropy" | "greenred" | "lock" | "carrier";

const VIEWS: { id: View; label: string }[] = [
  { id: "entropy", label: "Entropy" },
  { id: "greenred", label: "Green / Red" },
  { id: "lock", label: "Entity Lock" },
  { id: "carrier", label: "Carriers" },
];

const MAX_TOKENS = 6000;

function entropyColor(e: number): string {
  const t = Math.min(1, e / 4);
  const hue = 150 - 150 * t; // 150 green → 0 red
  const alpha = 0.12 + 0.28 * t;
  return `hsla(${hue}, 80%, 55%, ${alpha})`;
}

function bgFor(view: View, tok: Token): string {
  if (!tok.isWord) return "transparent";
  switch (view) {
    case "entropy":
      return entropyColor(tok.entropy);
    case "greenred":
      return tok.green
        ? "rgba(16,185,129,0.22)"
        : "rgba(244,63,94,0.16)";
    case "lock":
      return tok.lock === "LOCKED" ? "rgba(16,185,129,0.2)" : "transparent";
    case "carrier":
      return tok.lock === "MUTABLE" && tok.entropy > 2.2
        ? "rgba(244,63,94,0.22)"
        : tok.lock === "LOCKED"
          ? "rgba(16,185,129,0.12)"
          : "transparent";
  }
}

interface HoverState {
  tok: Token;
  x: number;
  y: number;
}

export function EntropyHeatmapViewer({ layer3 }: { layer3: Layer3Result }) {
  const [view, setView] = useState<View>("entropy");
  const [hover, setHover] = useState<HoverState | null>(null);

  const tokens = layer3.tokens.slice(0, MAX_TOKENS);
  const truncated = layer3.tokens.length > MAX_TOKENS;

  const verdictColor =
    layer3.verdict === "likely-watermarked"
      ? "#F43F5E"
      : layer3.verdict === "inconclusive"
        ? "#F59E0B"
        : "#10B981";

  return (
    <div className="glass p-6 relative">
      <div className="flex flex-wrap items-center gap-3 justify-between">
        <div className="flex items-center gap-2.5">
          <div
            className="grid place-items-center w-9 h-9 rounded-xl"
            style={{ background: "#06B6D422", color: "#22d3ee" }}
          >
            <Activity size={18} />
          </div>
          <div>
            <h3 className="text-base font-semibold tracking-tight">
              Layer 3 · SynthID & Entropy Ribbon
            </h3>
            <p className="text-xs text-muted">
              Per-token conditional entropy, green-list & tournament g (simulator)
            </p>
          </div>
        </div>

        {/* view toggle */}
        <div className="flex p-1 rounded-xl bg-white/5 border border-white/5">
          {VIEWS.map((v) => (
            <button
              key={v.id}
              onClick={() => setView(v.id)}
              className={`px-2.5 py-1 rounded-lg text-[0.72rem] font-medium transition ${
                view === v.id
                  ? "bg-[var(--analytic)] text-[#04131a]"
                  : "text-secondary hover:text-primary"
              }`}
            >
              {v.label}
            </button>
          ))}
        </div>
      </div>

      {/* stat strip */}
      <div className="flex flex-wrap gap-2 mt-4 mb-3">
        <span
          className="chip font-semibold"
          style={{ borderColor: `${verdictColor}66`, color: verdictColor }}
        >
          {layer3.verdict.replace(/-/g, " ")}
        </span>
        <span className="chip mono text-secondary">z = {layer3.zScore.toFixed(2)}</span>
        <span className="chip mono text-secondary">p = {layer3.pValue}</span>
        <span className="chip mono text-secondary">ḡ = {layer3.meanG.toFixed(3)}</span>
        <span className="chip mono text-secondary">
          green = {(layer3.greenFraction * 100).toFixed(1)}%
        </span>
        <span className="chip mono text-[#6ee7b7]">
          <Lock size={11} /> {layer3.lockedCount} locked
        </span>
        <span className="chip mono text-[#fda4af]">
          <Unlock size={11} /> {layer3.carrierCount} carriers
        </span>
      </div>

      {/* ribbon */}
      <div
        className="mono text-[0.82rem] leading-7 p-4 rounded-xl bg-black/30 border border-white/5 max-h-80 overflow-auto whitespace-pre-wrap"
        onMouseLeave={() => setHover(null)}
      >
        {tokens.map((tok, i) =>
          tok.isWord ? (
            <span
              key={i}
              className="tok"
              style={{ background: bgFor(view, tok) }}
              onMouseEnter={(e) =>
                setHover({ tok, x: e.clientX, y: e.clientY })
              }
              onMouseMove={(e) =>
                setHover((h) => (h ? { ...h, x: e.clientX, y: e.clientY } : h))
              }
            >
              {tok.text}
            </span>
          ) : (
            <span key={i}>{tok.text}</span>
          ),
        )}
        {truncated && (
          <span className="text-muted"> … (display truncated at {MAX_TOKENS} tokens)</span>
        )}
      </div>

      {/* legend */}
      <Legend view={view} />

      {/* hover HUD */}
      {hover && <HoverHud hover={hover} />}
    </div>
  );
}

function Legend({ view }: { view: View }) {
  const items: { c: string; label: string }[] =
    view === "entropy"
      ? [
          { c: "hsla(150,80%,55%,0.3)", label: "low H (locked facts)" },
          { c: "hsla(75,80%,55%,0.3)", label: "mid H" },
          { c: "hsla(0,80%,55%,0.4)", label: "high H (watermark carriers)" },
        ]
      : view === "greenred"
        ? [
            { c: "rgba(16,185,129,0.22)", label: "green list" },
            { c: "rgba(244,63,94,0.16)", label: "red list" },
          ]
        : view === "lock"
          ? [{ c: "rgba(16,185,129,0.2)", label: "ENTROPY_LOCKED entity" }]
          : [
              { c: "rgba(244,63,94,0.22)", label: "watermark carrier" },
              { c: "rgba(16,185,129,0.12)", label: "locked fact" },
            ];
  return (
    <div className="flex flex-wrap gap-3 mt-3">
      {items.map((it, i) => (
        <span key={i} className="flex items-center gap-1.5 text-[0.68rem] text-muted">
          <span
            className="w-3.5 h-3.5 rounded"
            style={{ background: it.c, border: "1px solid rgba(255,255,255,0.1)" }}
          />
          {it.label}
        </span>
      ))}
    </div>
  );
}

function HoverHud({ hover }: { hover: HoverState }) {
  const { tok, x, y } = hover;
  const cp = tok.text.codePointAt(0) ?? 0;
  const top = y + 18;
  const left = Math.min(x + 14, (typeof window !== "undefined" ? window.innerWidth : 1200) - 240);
  return (
    <div
      className="fixed z-50 pointer-events-none glass-strong p-3 w-56 text-[0.7rem]"
      style={{ top, left }}
    >
      <div className="mono text-sm font-semibold text-[var(--analytic)] break-all mb-1.5">
        “{tok.text}”
      </div>
      <Row k="Token #" v={String(tok.index)} />
      <Row k="Entropy H(x)" v={`${tok.entropy.toFixed(2)} bits`} />
      <Row
        k="Entity lock"
        v={tok.lock + (tok.lockReason ? ` (${tok.lockReason})` : "")}
        color={tok.lock === "LOCKED" ? "#6ee7b7" : "#94a3b8"}
      />
      <Row
        k="Green list"
        v={tok.green ? "GREEN" : "RED"}
        color={tok.green ? "#6ee7b7" : "#fda4af"}
      />
      <Row k="Tournament ḡ" v={tok.gScore.toFixed(3)} />
      <Row k="First codepoint" v={"U+" + cp.toString(16).toUpperCase().padStart(4, "0")} />
    </div>
  );
}

function Row({ k, v, color }: { k: string; v: string; color?: string }) {
  return (
    <div className="flex justify-between gap-2 py-0.5">
      <span className="text-muted">{k}</span>
      <span className="mono" style={{ color: color ?? "var(--text-primary)" }}>
        {v}
      </span>
    </div>
  );
}
