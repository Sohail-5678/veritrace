/**
 * POST /api/scan — Zero-trust forensic analysis of untrusted text or files.
 *
 * Accepts either:
 *   - application/json  { "text": "..." }
 *   - any other content-type → raw file bytes (x-filename header optional)
 *
 * Runs the input firewall, rate limiter, prompt-injection scanner, then
 * Layers 1–3. Nothing is persisted. Returns a ScanResult + security summary.
 */

import { NextRequest, NextResponse } from "next/server";
import { analyzeBytes, analyzeText } from "@/lib/forensics/analyze";
import { validateText, validateUpload, MAX_FILE_BYTES } from "@/lib/security/input-firewall";
import { scanForInjection } from "@/lib/security/prompt-guard";
import { checkRate, getClientId } from "@/lib/security/rate-limiter";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  const clientId = getClientId(req.headers);
  const rate = checkRate(clientId);
  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Rate limit exceeded.", retryAfterMs: rate.retryAfterMs },
      { status: 429, headers: { "retry-after": String(Math.ceil(rate.retryAfterMs / 1000)) } },
    );
  }

  const contentType = req.headers.get("content-type") ?? "";

  try {
    if (contentType.includes("application/json")) {
      const body = await req.json().catch(() => null);
      const text = typeof body?.text === "string" ? body.text : "";
      const v = validateText(text);
      if (!v.ok) return NextResponse.json({ error: v.reason }, { status: 400 });

      const scan = analyzeText(text);
      const injection = scanForInjection(text);
      return NextResponse.json(
        { scan, injection, rateRemaining: rate.remaining },
        { headers: rateHeaders(rate) },
      );
    }

    // binary upload
    const buf = await req.arrayBuffer();
    if (buf.byteLength > MAX_FILE_BYTES) {
      return NextResponse.json({ error: "Payload too large." }, { status: 413 });
    }
    const bytes = new Uint8Array(buf);
    const fw = validateUpload(bytes);
    if (!fw.ok) return NextResponse.json({ error: fw.reason }, { status: 400 });

    const fileName = req.headers.get("x-filename") ?? "";
    const result = await analyzeBytes(bytes, fileName);
    const injection = scanForInjection(result.extractedText);

    return NextResponse.json(
      {
        scan: result,
        injection,
        blockedPdfKeys: fw.blockedKeys ?? [],
        rateRemaining: rate.remaining,
      },
      { headers: rateHeaders(rate) },
    );
  } catch (err) {
    return NextResponse.json(
      { error: "Analysis failed.", detail: (err as Error).message },
      { status: 500 },
    );
  }
}

function rateHeaders(rate: { limit: number; remaining: number }): HeadersInit {
  return {
    "x-ratelimit-limit": String(rate.limit),
    "x-ratelimit-remaining": String(rate.remaining),
  };
}
