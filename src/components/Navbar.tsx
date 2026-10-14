"use client";

import { ShieldCheck, FlaskConical, Github, Fingerprint, Lock } from "lucide-react";

interface Props {
  onOpenSecurity: () => void;
  onOpenBenchmark: () => void;
  rateRemaining?: number;
}

export function Navbar({ onOpenSecurity, onOpenBenchmark }: Props) {
  return (
    <header className="sticky top-0 z-40 px-4 sm:px-6 pt-4">
      <nav className="glass max-w-7xl mx-auto px-4 sm:px-5 py-3 flex items-center gap-3">
        <div className="flex items-center gap-2.5">
          <div
            className="grid place-items-center w-9 h-9 rounded-xl"
            style={{
              background: "linear-gradient(135deg, #06B6D4, #8B5CF6)",
              boxShadow: "0 0 20px -4px #06B6D4",
            }}
          >
            <Fingerprint size={18} className="text-white" />
          </div>
          <div className="leading-tight">
            <div className="font-semibold tracking-tight text-[0.95rem]">VeriTrace</div>
            <div className="text-[0.62rem] text-muted hidden sm:block">
              AI Provenance Forensics
            </div>
          </div>
        </div>

        <div className="hidden md:flex items-center gap-1.5 ml-2">
          <span className="chip text-[#6ee7b7]" style={{ borderColor: "#10B98144" }}>
            <ShieldCheck size={12} /> Guardrails active
          </span>
          <span className="chip text-[#22d3ee]" style={{ borderColor: "#06B6D444" }}>
            <Lock size={12} /> Local-first · $0
          </span>
        </div>

        <div className="ml-auto flex items-center gap-1.5">
          <button onClick={onOpenSecurity} className="btn btn-ghost !py-2 !px-3 text-xs">
            <ShieldCheck size={14} />
            <span className="hidden sm:inline">Firewall</span>
          </button>
          <button onClick={onOpenBenchmark} className="btn btn-ghost !py-2 !px-3 text-xs">
            <FlaskConical size={14} />
            <span className="hidden sm:inline">Benchmark</span>
          </button>
          <a
            href="https://github.com/Sohail-5678/veritrace"
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-ghost !py-2 !px-3 text-xs"
          >
            <Github size={14} />
            <span className="hidden sm:inline">GitHub</span>
          </a>
        </div>
      </nav>
    </header>
  );
}
