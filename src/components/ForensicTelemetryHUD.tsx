"use client";

import type { ScanResult } from "@/lib/forensics/types";
import { RadialGauge } from "./Gauge";

const CLEAN = "#10B981";
const CAUTION = "#F59E0B";
const THREAT = "#F43F5E";

interface Props {
  scan: ScanResult;
}

export function ForensicTelemetryHUD({ scan }: Props) {
  const { layer1, layer2, layer3 } = scan;

  const zColor = layer3.zScore > 4 ? THREAT : layer3.zScore > 1.2 ? CAUTION : CLEAN;
  const gColor = layer3.meanG > 0.56 ? THREAT : layer3.meanG > 0.52 ? CAUTION : CLEAN;
  const riskColor =
    layer1.containerRiskScore > 60
      ? THREAT
      : layer1.containerRiskScore > 25
        ? CAUTION
        : CLEAN;
  const stegoColor =
    layer2.threatCount >= 3 ? THREAT : layer2.threatCount >= 1 ? CAUTION : CLEAN;

  return (
    <div className="glass p-5 sm:p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold tracking-tight flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-[var(--analytic)] animate-pulse" />
          Live Forensic Telemetry
        </h3>
        <span className="chip mono text-muted">{scan.elapsedMs} ms · local</span>
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <RadialGauge
          label="Kirchenbauer z-score"
          caption={`p = ${layer3.pValue}`}
          value={Math.max(0, layer3.zScore)}
          display={layer3.zScore.toFixed(2)}
          max={6}
          color={zColor}
        />
        <RadialGauge
          label="SynthID mean g"
          caption="human ≈ 0.500"
          value={layer3.meanG}
          min={0.45}
          max={0.62}
          display={layer3.meanG.toFixed(3)}
          color={gColor}
        />
        <RadialGauge
          label="Container risk"
          caption={layer1.applicable ? "0–100" : "n/a (text)"}
          value={layer1.containerRiskScore}
          max={100}
          display={String(layer1.containerRiskScore)}
          color={riskColor}
        />
        <RadialGauge
          label="Stego threats"
          caption={`${layer2.totalAnomalies} anomalies`}
          value={layer2.threatCount}
          max={Math.max(8, layer2.threatCount)}
          display={String(layer2.threatCount)}
          color={stegoColor}
        />
      </div>
    </div>
  );
}
