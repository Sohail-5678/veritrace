"use client";

import { motion } from "framer-motion";
import { Binary, EyeOff, Activity, Sparkles } from "lucide-react";
import { useState } from "react";
import type { ScanResult, Severity } from "@/lib/forensics/types";

interface Props {
  scan: ScanResult;
  onFocus: (layer: number) => void;
  sanitized: boolean;
}

const ICONS = [Binary, EyeOff, Activity, Sparkles];

const ACCENTS = ["#8B5CF6", "#F43F5E", "#06B6D4", "#10B981"];

function sevColor(sev: Severity): string {
  return sev === "threat" ? "#F43F5E" : sev === "caution" ? "#F59E0B" : "#10B981";
}

export function SpatialLayerStack({ scan, onFocus, sanitized }: Props) {
  const [hover, setHover] = useState<number | null>(null);

  const l1sev: Severity =
    scan.layer1.containerRiskScore > 60
      ? "threat"
      : scan.layer1.containerRiskScore > 25
        ? "caution"
        : "clean";
  const l2sev: Severity =
    scan.layer2.threatCount >= 3
      ? "threat"
      : scan.layer2.threatCount >= 1
        ? "caution"
        : "clean";
  const l3sev: Severity =
    scan.layer3.verdict === "likely-watermarked"
      ? "threat"
      : scan.layer3.verdict === "inconclusive"
        ? "caution"
        : "clean";

  const planes = [
    {
      title: "Binary & C2PA Container",
      stat: scan.layer1.applicable
        ? `risk ${scan.layer1.containerRiskScore}/100`
        : "plain text",
      detail: `${scan.layer1.findings.length} provenance signals`,
      sev: l1sev,
    },
    {
      title: "Unicode & Steganography",
      stat: `${scan.layer2.threatCount} threats`,
      detail: `${scan.layer2.totalAnomalies} invisible anomalies`,
      sev: l2sev,
    },
    {
      title: "SynthID & Entropy",
      stat: `z = ${scan.layer3.zScore.toFixed(2)}`,
      detail: `${scan.layer3.lockedCount} locked · ${scan.layer3.carrierCount} carriers`,
      sev: l3sev,
    },
    {
      title: "Sanitized Entity-Locked Output",
      stat: sanitized ? "sanitized ✓" : "ready to run",
      detail: sanitized ? "hygiene complete" : `${scan.layer3.lockedCount} entities to lock`,
      sev: sanitized ? ("clean" as Severity) : ("caution" as Severity),
    },
  ];

  return (
    <div className="glass p-6 overflow-hidden relative">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold tracking-tight">
          Exploded Forensic Layer Stack
        </h3>
        <span className="chip text-muted">click a plane to focus</span>
      </div>
      <p className="text-xs text-muted mb-4">
        A live 3D section of the document across all four analysis planes.
      </p>

      <div
        className="scene-3d mx-auto"
        style={{ height: 360, maxWidth: 520 }}
      >
        <div
          className="plane-3d relative mx-auto"
          style={{
            width: "78%",
            height: "100%",
            transform: "rotateX(52deg) rotateZ(-35deg) scale(0.92)",
          }}
        >
          {planes.map((p, i) => {
            const Icon = ICONS[i];
            const lifted = hover === i;
            const baseZ = i * 66;
            const accent = ACCENTS[i];
            return (
              <motion.div
                key={i}
                role="button"
                tabIndex={0}
                aria-label={`Focus ${p.title}`}
                onHoverStart={() => setHover(i)}
                onHoverEnd={() => setHover(null)}
                onClick={() => onFocus(i)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    onFocus(i);
                  }
                }}
                initial={{ opacity: 0, z: baseZ - 40 }}
                animate={{
                  opacity: 1,
                  z: lifted ? baseZ + 46 : baseZ,
                  boxShadow: lifted
                    ? `0 30px 60px -20px ${accent}, inset 0 1px 0 0 rgba(255,255,255,0.18)`
                    : "0 20px 40px -24px rgba(0,0,0,0.8), inset 0 1px 0 0 rgba(255,255,255,0.1)",
                }}
                transition={{
                  type: "spring",
                  stiffness: 260,
                  damping: 26,
                  delay: i * 0.08,
                }}
                className="absolute left-0 right-0 cursor-pointer outline-none"
                style={{
                  top: "28%",
                  height: 108,
                  transformStyle: "preserve-3d",
                  borderRadius: 14,
                  border: `1px solid ${accent}55`,
                  background:
                    "linear-gradient(135deg, rgba(16,22,36,0.86), rgba(10,14,22,0.7))",
                  backdropFilter: "blur(10px)",
                }}
              >
                <div
                  className="absolute inset-0 rounded-[13px] pointer-events-none"
                  style={{
                    background: `radial-gradient(60% 120% at 20% 0%, ${accent}22, transparent 70%)`,
                  }}
                />
                <div className="relative p-3.5 h-full flex flex-col justify-between">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div
                        className="grid place-items-center w-7 h-7 rounded-lg"
                        style={{ background: `${accent}22`, color: accent }}
                      >
                        <Icon size={15} />
                      </div>
                      <span className="text-[0.74rem] font-semibold tracking-tight">
                        {p.title}
                      </span>
                    </div>
                    <span
                      className="w-2.5 h-2.5 rounded-full"
                      style={{
                        background: sevColor(p.sev),
                        boxShadow: `0 0 10px ${sevColor(p.sev)}`,
                      }}
                    />
                  </div>
                  <div className="flex items-end justify-between">
                    <span className="mono text-lg font-semibold" style={{ color: accent }}>
                      {p.stat}
                    </span>
                    <span className="text-[0.64rem] text-muted">{p.detail}</span>
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>

      <div className="grid grid-cols-4 gap-2 mt-2">
        {planes.map((p, i) => (
          <button
            key={i}
            onClick={() => onFocus(i)}
            className="chip justify-center hover:bg-white/10 transition"
            style={{ borderColor: `${ACCENTS[i]}55` }}
          >
            <span className="text-[0.64rem]">L{i + 1}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
