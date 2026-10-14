/**
 * GET|POST /api/eval-benchmark — runs the 30-case statistical & red-team suite.
 * Deterministic and in-process; no external calls.
 */

import { NextRequest, NextResponse } from "next/server";
import { runBenchmark } from "@/lib/evals/benchmark-suite";
import { checkRate, getClientId } from "@/lib/security/rate-limiter";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function handle(req: NextRequest) {
  const rate = checkRate(getClientId(req.headers));
  if (!rate.allowed) {
    return NextResponse.json({ error: "Rate limit exceeded." }, { status: 429 });
  }
  const result = runBenchmark();
  return NextResponse.json({ result });
}

export async function GET(req: NextRequest) {
  return handle(req);
}
export async function POST(req: NextRequest) {
  return handle(req);
}
