"use client";

import type { Layer2Result, Severity } from "@/lib/forensics/types";
import { EyeOff, AlertTriangle, Languages } from "lucide-react";

function sevStyle(sev: Severity) {
  if (sev === "threat")
    return { border: "#F43F5E55", bg: "rgba(244,63,94,0.08)", color: "#fda4af" };
  if (sev === "caution")
    return { border: "#F59E0B55", bg: "rgba(245,158,11,0.08)", color: "#fcd34d" };
  return { border: "#10B98144", bg: "rgba(16,185,129,0.06)", color: "#6ee7b7" };
}

export function UnicodeStegoPanel({ layer2 }: { layer2: Layer2Result }) {
  return (
    <div className="glass p-6">
      <div className="flex items-center gap-2.5">
        <div
          className="grid place-items-center w-9 h-9 rounded-xl"
          style={{ background: "#F43F5E22", color: "#fb7185" }}
        >
          <EyeOff size={18} />
        </div>
        <div>
          <h3 className="text-base font-semibold tracking-tight">
            Layer 2 · Unicode Steganography
          </h3>
          <p className="text-xs text-muted">
            Invisible code points, ASCII-smuggling & homoglyph scanner
          </p>
        </div>
        <div className="ml-auto text-right">
          <div className="mono text-2xl font-bold text-[#fb7185]">
            {layer2.totalAnomalies}
          </div>
          <div className="text-[0.64rem] text-muted">anomalies</div>
        </div>
      </div>

      {/* decoded smuggled payload — the headline threat */}
      {layer2.decodedHiddenMessage && (
        <div
          className="mt-4 p-4 rounded-xl relative overflow-hidden"
          style={{ border: "1px solid #F43F5E", background: "rgba(244,63,94,0.12)" }}
        >
          <div className="scanline" />
          <div className="flex items-center gap-2 text-[#fda4af] text-xs font-semibold mb-2">
            <AlertTriangle size={14} />
            DECODED ASCII-SMUGGLED PAYLOAD (U+E00xx Tag block)
          </div>
          <code className="mono text-sm text-white break-words block">
            “{layer2.decodedHiddenMessage}”
          </code>
          <p className="text-[0.68rem] text-muted mt-2">
            This text was invisible in the document. Treated strictly as
            untrusted data — never executed. Layer 4 strips it entirely.
          </p>
        </div>
      )}

      {/* findings grid */}
      <div className="grid sm:grid-cols-2 gap-2.5 mt-4">
        {layer2.findings.map((f, i) => {
          const s = sevStyle(f.severity);
          return (
            <div
              key={i}
              className="p-3 rounded-xl"
              style={{ border: `1px solid ${s.border}`, background: s.bg }}
            >
              <div className="flex items-center justify-between">
                <span className="mono text-xs font-semibold" style={{ color: s.color }}>
                  {f.label}
                </span>
                <span className="mono text-xs text-muted">×{f.count}</span>
              </div>
              <div className="text-[0.78rem] font-medium mt-0.5">{f.name}</div>
              <p className="text-[0.66rem] text-muted mt-1 leading-snug">{f.note}</p>
            </div>
          );
        })}
        {layer2.findings.length === 0 && (
          <div className="text-sm text-[#6ee7b7] col-span-full py-6 text-center">
            No invisible or deceptive code points detected — text is clean.
          </div>
        )}
      </div>

      {/* homoglyphs */}
      {layer2.homoglyphHits.length > 0 && (
        <div className="mt-4">
          <h4 className="text-xs font-semibold text-secondary mb-2 flex items-center gap-1.5">
            <Languages size={13} /> Homoglyph Substitutions
          </h4>
          <div className="flex flex-wrap gap-2">
            {layer2.homoglyphHits.slice(0, 12).map((h, i) => (
              <span key={i} className="chip mono text-[0.68rem]" title={`${h.script} script`}>
                <span className="text-[#fda4af]">{h.word}</span>
                <span className="text-muted">→</span>
                <span className="text-[#6ee7b7]">{h.normalized}</span>
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
