<div align="center">

# 🔬 VeriTrace

### Multi-Layer AI Provenance Forensics · SynthID / Entropy Analyzer · Zero-Trust Document Hygiene

**Trace the provenance of any document — local-first, at `$0`, with files that never leave the browser.**

`Next.js 15` · `React 19` · `TypeScript` · `Tailwind` · `Framer Motion` · `pdf-lib` · `Vitest`

</div>

---

## What it is

VeriTrace is a four-layer document forensics and hygiene engine. It inspects PDFs, DOCX and raw text for the fingerprints that cloud / headless AI renderers leave behind, detects invisible Unicode steganography and prompt-injection payloads, visualizes statistical text-watermark signatures (SynthID-Text & Kirchenbauer green-list **simulators**, for education), and performs **entity-locked sanitization** that strips hidden channels and tracking canaries while guaranteeing that every number, date, name and technical term is preserved byte-for-byte.

It runs **entirely in your browser** by default — no uploads, no database, no API key, no cost. Optional server API routes and a BYOK Groq style-pass are included and fully guarded, but off by default.

> **Responsible use.** VeriTrace is for document hygiene, privacy, and defensive-security research and education. The watermark layer is a transparent *simulator* that shows how these schemes work; the sanitizer removes hidden injections, tracking canaries and typographic noise and polishes writing style. It is **not** a tool for misrepresenting the authorship or provenance of AI-generated content, and the UI/README say so throughout.

---

## ✨ Two ways to use it

| Mode | What you get |
| :--- | :--- |
| **🧪 Demo Sandbox** (zero-click) | Three pre-loaded forensic artifacts with **real embedded anomalies** — an AI-customised résumé (watermark sim), a canary-watermarked M&A memo, and an adversarial vendor invoice carrying an invisible prompt injection. Explore the 3D layer stack, entropy heatmap and diff viewer instantly. |
| **📤 Use Your Own** | Drag-drop a `.pdf` / `.docx` / `.txt` / `.md` / `.tex`, or paste text. Layers 1–4 run locally in `<300 ms`. Download a clean, rebuilt PDF. |

Every screen has an exit path: close buttons, `Esc`, click-outside, "back to top", and a persistent mode toggle.

---

## 🧠 The four forensic layers

### Layer 1 — Binary, Font-Subset & C2PA Container Forensics
Scans raw bytes (no text extraction needed) for `/Producer`, `/Creator`, XMP packets, **C2PA / JUMBF** content-credential manifests, container font subsets (`DejaVuSans`, `Liberation`, `Nimbus`…) and dangerous active-content keys (`/JavaScript`, `/OpenAction`, `/Launch`…). Produces a `0–100` container-provenance risk score.

### Layer 2 — Unicode Steganography & ASCII-Smuggling Scanner
Walks every code point and classifies 35+ invisible / deceptive characters: zero-width controls (`U+200B`–`U+200F`, `U+2060`), the **Unicode Tag block** `U+E0000`–`U+E007F` (**and decodes any smuggled payload**), variation selectors, narrow/no-break spaces (`U+202F`, `U+00A0`), em-dash density, and mixed-script homoglyphs.

### Layer 3 — SynthID-Text Tournament & Kirchenbauer Green-List Simulator
Transparent, deterministic math at the token level:

- **Green-list z-score** with green fraction $\gamma = 0.5$:

$$z = \frac{|S|_G - \gamma T}{\sqrt{T\,\gamma(1-\gamma)}}, \qquad p = 1 - \Phi(z) = \tfrac{1}{2}\,\mathrm{erfc}\!\left(\tfrac{z}{\sqrt 2}\right)$$

- **SynthID tournament mean g-score** over $m = 30$ layers:

$$\bar g = \frac{1}{T\,m}\sum_{t=1}^{T}\sum_{\ell=1}^{m} g_\ell(w_t, r_t)$$

- **Entropy masking** — per-token conditional entropy $H(X_t \mid X_{<t})$ estimated by lexical substitutability. Low-entropy tokens (numbers, dates, technical nouns) are `ENTROPY_LOCKED` and can never carry a watermark; high-entropy tokens are `WATERMARK_CARRIER`s.

> **Honest by design:** a real detector only fires on text watermarked under the key it probes; arbitrary human text gives $z \approx 0$, and the UI reports exactly that. The pre-loaded demo artifacts pass `simulateWatermark: true`, which biases **only** the substitutable (non-factual) tokens — so you can see what a watermarked document looks like without the engine ever fabricating a signal on your own input.

### Layer 4 — Entity-Locked Sanitizer & Clean-Room PDF Builder
1. **Extract & freeze** all factual entities (`$250K+`, `97%+`, dates, URLs, emails, `LangGraph`, `pgvector`, `Cohen's kappa`…).
2. **Hygiene:** strip invisible / smuggling code points, normalise exotic spaces to ASCII, tame em-dash runs, and clean stylistic "AI tells" (puffery adverbs, participial tail-clauses) — with locked entities masked so they're untouchable.
3. **Verification gate:** recompute **entity-lock recall**. Anything below 100% is rolled back to a guaranteed loss-free result.
4. **Clean-room PDF:** rebuild a brand-new PDF from scratch with clean desktop metadata (`pdf-lib`), downloadable.

---

## 🛡️ Fortress-grade security (5 guardrails)

1. **Spotlighting** — untrusted document text is wrapped in a per-request cryptographic boundary nonce and datamarked; break-out attempts are escaped. *(`src/lib/security/prompt-guard.ts`)*
2. **OWASP LLM01 injection scanner** — deterministic regex/heuristic detector for instruction-override, jailbreak and exfiltration attempts; blocks the optional LLM call when triggered.
3. **Canary exfiltration trap** — an ephemeral `CANARY-VT-*` token is planted in LLM context; the output guard aborts on any canary/secret/env-var leak.
4. **Input firewall** — magic-byte verification, polyglot detection, size caps (4.5 MB / 50 k chars), UTF-8 validation, zip-bomb ratio guard, and PDF active-content enumeration. *(`src/lib/security/input-firewall.ts`)*
5. **Rate limiting & CSP** — in-memory token bucket (`15 req/min/IP`) with an optional HMAC client challenge, plus strict CSP, `X-Frame-Options: DENY`, `nosniff`, HSTS and a locked-down `Permissions-Policy`. *(`next.config.ts`, `src/lib/security/rate-limiter.ts`)*

Try them live in the **Red-Team Firewall Tester** (navbar → Firewall).

---

## 📊 Built-in evaluation (navbar → Benchmark)

A deterministic, in-process 30-case suite:

| Metric | Target | Typical |
| :--- | :--- | :--- |
| Watermark detection **ROC-AUC** | > 0.9 | ~1.00 |
| **TPR @ 1% FPR** | > 0.8 | ~1.00 |
| Paired **Δz** after hygiene | large | ~3–4 |
| **Entity-lock fidelity** | 100% | 100% |
| **Red-team block rate** (12 payloads) | 100% | 100% |

---

## 💸 Why it costs `$0`

| Component | Choice | Cost |
| :--- | :--- | :--- |
| Frontend + API | Next.js 15 on Vercel Hobby | $0 |
| Forensic engines | Pure TS, run in-browser / Edge | $0 |
| PDF parse / rebuild | `pdf-lib` + platform `DecompressionStream` | $0 |
| Sanitizer | Deterministic local engine (default) | $0 |
| Persistence | **None** — stateless, nothing touches disk | $0 |
| Optional LLM pass | Groq free tier, **BYOK**, off by default | $0 |

---

## 🚀 Quickstart

```bash
npm install
npm run dev        # http://localhost:3000
npm test           # 24 unit + security tests
npm run build      # production build
```

No environment variables are required. See `.env.example` for the optional `GROQ_API_KEY` and rate-limit settings.

### Deploy (Vercel)

```bash
vercel --prod
```

The app is a standard Next.js App Router project — push to GitHub and import into Vercel, or use the CLI above.

---

## 🗂️ Project structure

```
veritrace/
├── src/
│   ├── app/
│   │   ├── page.tsx                 # Spatial forensic command center
│   │   ├── layout.tsx · globals.css # Obsidian-glass design system
│   │   └── api/{scan,sanitize,eval-benchmark}/route.ts
│   ├── components/                  # Navbar, SpatialLayerStack, EntropyHeatmapViewer,
│   │                                #   BinaryForensicsPanel, UnicodeStegoPanel,
│   │                                #   SurgicalDiffMatrix, SecurityGuardrailModal,
│   │                                #   EvalBenchmarkDrawer, ForensicTelemetryHUD, Gauge
│   └── lib/
│       ├── forensics/               # layer1-binary, layer2-unicode, layer3-entropy,
│       │                            #   layer4-sanitizer, analyze, groq-rewrite
│       ├── security/                # input-firewall, prompt-guard, rate-limiter
│       ├── evals/benchmark-suite.ts
│       └── demo-artifacts.ts
└── tests/                           # forensics.test.ts · security.test.ts
```

---

## 🎨 Design — "Obsidian Glass & Bioluminescent Forensics"

Deep obsidian canvas with a cursor-reactive aurora, VisionOS-style frosted glass panels (`backdrop-filter: blur(24px) saturate(180%)`), a CSS-3D exploded isometric layer stack, an interactive token-entropy ribbon with a floating hover HUD, animated radial telemetry gauges, and semantic forensic accents — emerald (locked facts), amber (stylistic tells), crimson (threats) and electric cyan. Fully keyboard-accessible and `prefers-reduced-motion` aware.

---

## ⚖️ License & disclaimer

MIT. VeriTrace is a research, education and document-hygiene tool. The watermark layer is an illustrative simulator, not an interface to any production watermarking service. Use it to understand provenance signals, clean hidden/malicious content, and harden inbound-document pipelines — not to misrepresent the origin of generated text.

<div align="center">

**Built by [Ameer Sohail Shaik](https://ameer-shaik.vercel.app/)** · [github.com/Sohail-56781](https://github.com/Sohail-56781)

</div>
