/**
 * POST /api/sanitize — Entity-locked document hygiene & optional clean-PDF.
 *
 * Body (application/json):
 *   {
 *     "text": "...",                       // required
 *     "engine": "local" | "groq",          // default "local"
 *     "apiKey": "gsk_...",                  // optional BYOK (never stored)
 *     "buildPdf": true,                     // optional
 *     "title": "Document"                   // optional, for the clean PDF
 *   }
 *
 * The local deterministic engine is the default and always the fallback. The
 * Groq pass only runs when a key is supplied AND no injection is detected.
 */

import { NextRequest, NextResponse } from "next/server";
import { sanitizeLocal, buildCleanPdf, extractEntities } from "@/lib/forensics/layer4-sanitizer";
import { groqStyleRewrite } from "@/lib/forensics/groq-rewrite";
import { validateText } from "@/lib/security/input-firewall";
import { scanForInjection } from "@/lib/security/prompt-guard";
import { checkRate, getClientId } from "@/lib/security/rate-limiter";
import { scanUnicode } from "@/lib/forensics/layer2-unicode";
import { computeLayer3 } from "@/lib/forensics/layer3-entropy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  const clientId = getClientId(req.headers);
  const rate = checkRate(clientId);
  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Rate limit exceeded.", retryAfterMs: rate.retryAfterMs },
      { status: 429 },
    );
  }

  const body = await req.json().catch(() => null);
  const text = typeof body?.text === "string" ? body.text : "";
  const v = validateText(text);
  if (!v.ok) return NextResponse.json({ error: v.reason }, { status: 400 });

  const injection = scanForInjection(text);

  // Always compute the deterministic local result first (safe + loss-free).
  const result = sanitizeLocal(text);

  let engine = result.engine;
  let groqNote: string | undefined;

  const wantGroq = body?.engine === "groq";
  const apiKey =
    (typeof body?.apiKey === "string" && body.apiKey) || process.env.GROQ_API_KEY || "";

  if (wantGroq) {
    if (injection.detected) {
      groqNote =
        "Prompt-injection detected in input — external LLM call BLOCKED (OWASP LLM01). Local engine used.";
    } else if (!apiKey) {
      groqNote = "No API key available — local engine used.";
    } else {
      const locks = extractEntities(result.sanitized);
      const rewrite = await groqStyleRewrite(result.sanitized, locks, apiKey);
      if (rewrite && rewrite.text && !rewrite.blocked) {
        // Re-verify the LLM output through the same gate.
        const after = {
          zScore: computeLayer3(rewrite.text, { simulateWatermark: false }).zScore,
          pValue: computeLayer3(rewrite.text, { simulateWatermark: false }).pValue,
          meanG: computeLayer3(rewrite.text, { simulateWatermark: false }).meanG,
          anomalyCount: scanUnicode(rewrite.text).totalAnomalies,
        };
        result.sanitized = rewrite.text;
        result.after = after;
        engine = "groq-byok";
        result.notes.push("Groq style-polish applied and re-verified (entity recall 100%).");
      } else {
        groqNote = rewrite?.blocked
          ? `Output guard: ${rewrite.blocked} Local engine used.`
          : "Groq pass failed verification — local engine used (fallback).";
      }
    }
  }

  let pdfBase64: string | undefined;
  if (body?.buildPdf) {
    try {
      const pdf = await buildCleanPdf(result.sanitized, {
        title: typeof body?.title === "string" ? body.title : "Sanitized Document",
      });
      pdfBase64 = Buffer.from(pdf).toString("base64");
    } catch {
      /* non-fatal */
    }
  }

  return NextResponse.json({
    result: { ...result, engine },
    injection,
    groqNote,
    pdfBase64,
    rateRemaining: rate.remaining,
  });
}
