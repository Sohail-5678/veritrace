"use client";

import { useEffect, useRef } from "react";

/**
 * Ambient obsidian backdrop: a static dot-matrix grid plus an aurora depth
 * glow whose position eases toward the cursor. Purely decorative; respects
 * prefers-reduced-motion by simply not tracking the pointer.
 */
export function AuroraBackdrop() {
  const auroraRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const reduce = window.matchMedia(
      "(prefers-reduced-motion: reduce)",
    ).matches;
    if (reduce) return;

    let frame = 0;
    const onMove = (e: MouseEvent) => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const el = auroraRef.current;
        if (!el) return;
        const mx = (e.clientX / window.innerWidth) * 100;
        const my = (e.clientY / window.innerHeight) * 100;
        el.style.setProperty("--mx", `${mx.toFixed(1)}%`);
        el.style.setProperty("--my", `${my.toFixed(1)}%`);
      });
    };
    window.addEventListener("mousemove", onMove, { passive: true });
    return () => {
      window.removeEventListener("mousemove", onMove);
      cancelAnimationFrame(frame);
    };
  }, []);

  return (
    <>
      <div className="vt-backdrop" aria-hidden />
      <div className="vt-aurora" ref={auroraRef} aria-hidden />
    </>
  );
}
