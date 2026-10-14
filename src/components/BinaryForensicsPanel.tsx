"use client";

import type { Layer1Result, Severity } from "@/lib/forensics/types";
import { Binary, FileWarning, Type, ShieldCheck } from "lucide-react";
import { formatBytes } from "@/lib/utils";

function dot(sev: Severity) {
  const c = sev === "threat" ? "#F43F5E" : sev === "caution" ? "#F59E0B" : "#10B981";
  return (
    <span
      className="inline-block w-2 h-2 rounded-full shrink-0 mt-1.5"
      style={{ background: c, boxShadow: `0 0 8px ${c}` }}
    />
  );
}

export function BinaryForensicsPanel({ layer1 }: { layer1: Layer1Result }) {
  if (!layer1.applicable) {
    return (
      <div className="glass p-6">
        <PanelHead />
        <div className="mt-4 text-sm text-secondary flex items-center gap-2">
          <Type size={16} className="text-[var(--analytic)]" />
          {layer1.summary}
        </div>
      </div>
    );
  }

  const risk = layer1.containerRiskScore;
  const riskColor = risk > 60 ? "#F43F5E" : risk > 25 ? "#F59E0B" : "#10B981";

  return (
    <div className="glass p-6">
      <PanelHead />

      {/* risk meter */}
      <div className="mt-4 mb-5">
        <div className="flex justify-between text-xs mb-1.5">
          <span className="text-secondary">Container Provenance Risk</span>
          <span className="mono font-semibold" style={{ color: riskColor }}>
            {risk}/100
          </span>
        </div>
        <div className="h-2 rounded-full bg-white/5 overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-700"
            style={{
              width: `${risk}%`,
              background: `linear-gradient(90deg, ${riskColor}, ${riskColor}aa)`,
              boxShadow: `0 0 12px ${riskColor}`,
            }}
          />
        </div>
        <p className="text-xs text-muted mt-2">{layer1.summary}</p>
      </div>

      {/* findings */}
      <div className="space-y-2.5">
        {layer1.findings.map((f, i) => (
          <div
            key={i}
            className="flex gap-3 p-3 rounded-xl bg-white/[0.03] border border-white/5"
          >
            {dot(f.severity)}
            <div className="min-w-0">
              <div className="flex flex-wrap items-baseline gap-x-2">
                <span className="mono text-[0.78rem] font-semibold text-[var(--analytic)]">
                  {f.key}
                </span>
                <span className="mono text-[0.78rem] text-primary break-all">
                  {f.value}
                </span>
              </div>
              <p className="text-xs text-muted mt-0.5">{f.explanation}</p>
            </div>
          </div>
        ))}
      </div>

      {/* fonts + active content */}
      <div className="grid sm:grid-cols-2 gap-4 mt-5">
        <div>
          <h4 className="text-xs font-semibold text-secondary mb-2 flex items-center gap-1.5">
            <Type size={13} /> Font Subsets
          </h4>
          <div className="flex flex-wrap gap-1.5">
            {layer1.fonts.map((font, i) => (
              <span
                key={i}
                className="chip mono text-[0.68rem]"
                style={{
                  borderColor: font.container ? "#F43F5E55" : "#10B98144",
                  color: font.container ? "#fda4af" : "#6ee7b7",
                }}
                title={font.note}
              >
                {font.name}
              </span>
            ))}
            {layer1.fonts.length === 0 && (
              <span className="text-xs text-muted">none detected</span>
            )}
          </div>
        </div>
        <div>
          <h4 className="text-xs font-semibold text-secondary mb-2 flex items-center gap-1.5">
            <FileWarning size={13} /> Active Content
          </h4>
          {layer1.activeContentKeys.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {layer1.activeContentKeys.map((k) => (
                <span
                  key={k}
                  className="chip mono text-[0.68rem]"
                  style={{ borderColor: "#F43F5E55", color: "#fda4af" }}
                >
                  {k}
                </span>
              ))}
            </div>
          ) : (
            <span className="text-xs text-[#6ee7b7] flex items-center gap-1.5">
              <ShieldCheck size={13} /> none — no auto-executing code
            </span>
          )}
        </div>
      </div>

      <div className="mt-4 flex items-center gap-2 text-[0.7rem] text-muted mono">
        <span>{formatBytes(layer1.byteLength)}</span>·
        <span>{layer1.fileType.toUpperCase()}</span>·
        <span>{layer1.c2paDetected ? "C2PA manifest present" : "no C2PA manifest"}</span>
      </div>
    </div>
  );
}

function PanelHead() {
  return (
    <div className="flex items-center gap-2.5">
      <div
        className="grid place-items-center w-9 h-9 rounded-xl"
        style={{ background: "#8B5CF622", color: "#a78bfa" }}
      >
        <Binary size={18} />
      </div>
      <div>
        <h3 className="text-base font-semibold tracking-tight">
          Layer 1 · Binary & C2PA Container
        </h3>
        <p className="text-xs text-muted">
          Producer / XMP / C2PA / font-subset provenance forensics
        </p>
      </div>
    </div>
  );
}
