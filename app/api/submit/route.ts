import { NextResponse } from "next/server";
import {
  checkRateLimit,
  recordSubmission,
  computeScore,
  scoreToGrade,
  NUM_CHECKS,
  type CheckResult,
  type SubmitPayload,
} from "@/lib/haveibeenclawned";

const VALID_GRADES = new Set(["A", "B", "C", "D", "F"]);
const VALID_RESULTS = new Set([1, 0, 2, -1]);

export async function POST(request: Request) {
  try {
    const ip =
      request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
      "unknown";

    if (!checkRateLimit(ip)) {
      return NextResponse.json(
        { error: "Rate limit exceeded. Try again later." },
        { status: 429 }
      );
    }

    const body = await request.json();
    const { v, s, g, r } = body as {
      v?: number;
      s?: number;
      g?: string;
      r?: number[];
    };

    if (v !== 3) {
      return NextResponse.json(
        { error: "Unsupported version. Must be v:3." },
        { status: 400 }
      );
    }

    if (!g || !VALID_GRADES.has(g)) {
      return NextResponse.json(
        { error: "Invalid grade. Must be A-F." },
        { status: 400 }
      );
    }

    if (!Array.isArray(r) || r.length !== NUM_CHECKS) {
      return NextResponse.json(
        { error: `results must be an array of ${NUM_CHECKS} values` },
        { status: 400 }
      );
    }

    for (let i = 0; i < r.length; i++) {
      if (!VALID_RESULTS.has(r[i])) {
        return NextResponse.json(
          { error: `Invalid result at index ${i}. Must be 1, 0, 2, or -1.` },
          { status: 400 }
        );
      }
    }

    if (typeof s !== "number" || s < 0 || s > 100) {
      return NextResponse.json(
        { error: "Score must be 0-100." },
        { status: 400 }
      );
    }

    // Verify score and grade match results (prevent tampering)
    const expectedScore = computeScore(r as CheckResult[]);
    const expectedGrade = scoreToGrade(expectedScore);
    if (expectedScore !== s || expectedGrade !== g) {
      return NextResponse.json(
        { error: "Score/grade does not match check results" },
        { status: 400 }
      );
    }

    await recordSubmission(ip, {
      v: 3,
      s: s,
      g: g as SubmitPayload["g"],
      r: r as CheckResult[],
    });

    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json(
      { error: "Invalid request body" },
      { status: 400 }
    );
  }
}
