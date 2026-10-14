"use client";

import { motion } from "framer-motion";
import { useMemo } from "react";

interface GaugeProps {
  label: string;
  value: number;
  min?: number;
  max: number;
  unit?: string;
  display?: string; // override the printed value
  color: string; // resolved color
  caption?: string;
  size?: number;
}

/**
 * A 270°-sweep radial SVG gauge with an animated arc. Purely presentational.
 */
export function RadialGauge({
  label,
  value,
  min = 0,
  max,
  unit = "",
  display,
  color,
  caption,
  size = 132,
}: GaugeProps) {
  const stroke = 9;
  const r = (size - stroke * 2) / 2;
  const cx = size / 2;
  const cy = size / 2;
  const sweep = 270; // degrees
  const circumference = 2 * Math.PI * r;
  const arcLen = (sweep / 360) * circumference;

  const frac = useMemo(() => {
    const f = (value - min) / (max - min);
    return Math.max(0, Math.min(1, f));
  }, [value, min, max]);

  const rotation = 135; // start at lower-left

  return (
    <div className="flex flex-col items-center gap-1.5">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="block">
          <g transform={`rotate(${rotation} ${cx} ${cy})`}>
            {/* track */}
            <circle
              cx={cx}
              cy={cy}
              r={r}
              fill="none"
              stroke="rgba(255,255,255,0.07)"
              strokeWidth={stroke}
              strokeLinecap="round"
              strokeDasharray={`${arcLen} ${circumference}`}
            />
            {/* value arc */}
            <motion.circle
              cx={cx}
              cy={cy}
              r={r}
              fill="none"
              stroke={color}
              strokeWidth={stroke}
              strokeLinecap="round"
              strokeDasharray={`${arcLen} ${circumference}`}
              initial={{ strokeDashoffset: arcLen }}
              animate={{ strokeDashoffset: arcLen * (1 - frac) }}
              transition={{ duration: 1.1, ease: [0.22, 1, 0.36, 1] }}
              style={{ filter: `drop-shadow(0 0 6px ${color})` }}
            />
          </g>
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="mono text-2xl font-semibold" style={{ color }}>
            {display ?? value}
            {unit && <span className="text-sm text-muted ml-0.5">{unit}</span>}
          </span>
        </div>
      </div>
      <div className="text-center">
        <div className="text-[0.72rem] font-medium text-secondary tracking-tight">
          {label}
        </div>
        {caption && <div className="text-[0.64rem] text-muted mono">{caption}</div>}
      </div>
    </div>
  );
}
