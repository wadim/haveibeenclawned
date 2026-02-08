// Have I Been Clawned — v3: 72 checks, weighted scoring 0-100, OWASP-mapped

import checksJson from "@/data/checks.json";
import type { CheckDefinition } from "@/data/checks.types";

// ── Types ────────────────────────────────────────────────────────────────────

/** 1=pass, 0=fail, 2=warn, -1=skip */
export type CheckResult = 1 | 0 | 2 | -1;

export type Grade = "A" | "B" | "C" | "D" | "F";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM";

export interface CheckMeta {
  id: string;
  label: string;
  severity: Severity;
  points: number;
  owasp?: string;
  cve?: string;
  cwe?: string;
  atlas?: string;
  nist?: string;
  description: string;
}

// ── Check definitions (derived from data/checks.json — single source of truth)

export const CHECKS: CheckMeta[] = (checksJson as CheckDefinition[]).map((c) => ({
  id: c.id,
  label: c.title,
  severity: c.severity,
  points: c.points,
  ...(c.owasp && { owasp: c.owasp }),
  ...(c.cve && { cve: c.cve }),
  ...(c.cwe && { cwe: c.cwe }),
  ...(c.atlas && { atlas: c.atlas }),
  ...(c.nist && { nist: c.nist }),
  description: c.description,
}));

export const NUM_CHECKS = CHECKS.length; // 72

// ── Reference URL helpers ───────────────────────────────────────────────────

export function cveUrl(cve: string): string {
  return `https://nvd.nist.gov/vuln/detail/${cve}`;
}

export function cweUrl(cwe: string): string {
  const num = cwe.replace("CWE-", "");
  return `https://cwe.mitre.org/data/definitions/${num}.html`;
}

export function owaspUrl(owasp: string): string {
  return `https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/#${owasp.toLowerCase()}`;
}
export const MAX_POINTS = CHECKS.reduce((sum, c) => sum + c.points, 0); // 785

// ── Scan Report ─────────────────────────────────────────────────────────────

export interface ScanReport {
  v: 3;
  /** Hardening score 0-100 */
  s: number;
  /** Grade A-F */
  g: Grade;
  /** 72 results ordered by check # (CLAW-01 through CLAW-72) */
  r: CheckResult[];
  /** ISO date string */
  t: string;
}

// ── Legacy formats (backwards compat) ───────────────────────────────────────

// v1: 6 named checks
type V1CheckId = "pe" | "pk" | "ms" | "cs" | "ep" | "sb";
type V1CheckResults = Record<V1CheckId, 1 | 0 | -1>;
interface ScanReportV1 {
  g: Grade;
  c: V1CheckResults;
  t: string;
}

// v2: 15-element array
interface ScanReportV2 {
  v: 2;
  s: number;
  g: Grade;
  r: CheckResult[];
  t: string;
}

/** v1 → v3: map 6 checks to 30-element array */
function convertV1toV3(v1: ScanReportV1): ScanReport {
  const r: CheckResult[] = new Array(NUM_CHECKS).fill(-1) as CheckResult[];
  r[0] = v1.c.ep; // CLAW-01 <- ep (public endpoint)
  r[3] = v1.c.pe; // CLAW-04 <- pe (personal email)
  r[4] = v1.c.pk; // CLAW-05 <- pk (plaintext keys)
  r[6] = v1.c.cs; // CLAW-07 <- cs (conversation secrets)
  r[9] = v1.c.sb; // CLAW-10 <- sb (sandboxing)
  r[12] = v1.c.ms; // CLAW-13 <- ms (malicious skills)

  const s = computeScore(r);
  const g = scoreToGrade(s);
  return { v: 3, s, g, r, t: v1.t };
}

/** v2 → v3: expand 15-element array to 30, padding with skips */
function convertV2toV3(v2: ScanReportV2): ScanReport {
  const r: CheckResult[] = new Array(NUM_CHECKS).fill(-1) as CheckResult[];
  // v2 had 15 checks in positions 0-14. Map to new numbering:
  // v2[0-6] = CLAW-01 to CLAW-07 (CRITICAL, same)
  // v2[7] = CLAW-08 (sandbox) → now CLAW-10
  // v2[8] = CLAW-09 (elevated) → now CLAW-11
  // v2[9] = CLAW-10 (config perms) → now CLAW-12
  // v2[10] = CLAW-11 (skills) → now CLAW-13
  // v2[11] = CLAW-12 (MCP) → now CLAW-14
  // v2[12] = CLAW-13 (version) → now CLAW-15
  // v2[13] = CLAW-14 (session perms) → now CLAW-16
  // v2[14] = CLAW-15 (log redaction) → now CLAW-28
  for (let i = 0; i < 7; i++) r[i] = v2.r[i]; // CLAW-01 to CLAW-07
  r[9] = v2.r[7]; // sandbox → CLAW-10
  r[10] = v2.r[8]; // elevated → CLAW-11
  r[11] = v2.r[9]; // config perms → CLAW-12
  r[12] = v2.r[10]; // skills → CLAW-13
  r[13] = v2.r[11]; // MCP → CLAW-14
  r[14] = v2.r[12]; // version → CLAW-15
  r[15] = v2.r[13]; // session perms → CLAW-16
  r[27] = v2.r[14]; // log redaction → CLAW-28

  const s = computeScore(r);
  const g = scoreToGrade(s);
  return { v: 3, s, g, r, t: v2.t };
}

// ── Scoring ─────────────────────────────────────────────────────────────────

export function computeScore(results: CheckResult[]): number {
  let earned = 0;
  let possible = 0;

  for (let i = 0; i < CHECKS.length; i++) {
    const result = results[i];
    if (result === -1) continue; // skip — excluded from scoring
    const pts = CHECKS[i].points;
    possible += pts;
    if (result === 1) earned += pts;
    else if (result === 2) earned += Math.floor(pts / 2); // warn = half
  }

  if (possible === 0) return 100; // all skipped
  return Math.round((earned / possible) * 100);
}

export function scoreToGrade(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

// ── Encode / Decode (base64url, no backend needed) ──────────────────────────

export function encodeReport(report: ScanReport): string {
  const json = JSON.stringify(report);
  return btoa(json)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function decodeReport(encoded: string): ScanReport | null {
  try {
    let b64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    const json = atob(b64);
    const parsed = JSON.parse(json);

    // v3 format (current: 72 checks, or legacy 63/50/30 checks)
    if (parsed.v === 3 && Array.isArray(parsed.r)) {
      if (parsed.r.length === NUM_CHECKS) {
        return parsed as ScanReport;
      }
      // Legacy v3 with 63 checks — pad to 72 with skips
      if (parsed.r.length === 63) {
        const r: CheckResult[] = [
          ...parsed.r,
          ...new Array(NUM_CHECKS - 63).fill(-1),
        ] as CheckResult[];
        const s = computeScore(r);
        const g = scoreToGrade(s);
        return { v: 3, s, g, r, t: parsed.t };
      }
      // Legacy v3 with 50 checks — pad to 72 with skips
      if (parsed.r.length === 50) {
        const r: CheckResult[] = [
          ...parsed.r,
          ...new Array(NUM_CHECKS - 50).fill(-1),
        ] as CheckResult[];
        const s = computeScore(r);
        const g = scoreToGrade(s);
        return { v: 3, s, g, r, t: parsed.t };
      }
      // Legacy v3 with 30 checks — pad to 72 with skips
      if (parsed.r.length === 30) {
        const r: CheckResult[] = [
          ...parsed.r,
          ...new Array(NUM_CHECKS - 30).fill(-1),
        ] as CheckResult[];
        const s = computeScore(r);
        const g = scoreToGrade(s);
        return { v: 3, s, g, r, t: parsed.t };
      }
    }

    // v2 format (15 checks)
    if (parsed.v === 2 && Array.isArray(parsed.r) && parsed.r.length === 15) {
      return convertV2toV3(parsed as ScanReportV2);
    }

    // v1 format (6 named checks)
    if (parsed.g && parsed.c && parsed.t && !parsed.v) {
      return convertV1toV3(parsed as ScanReportV1);
    }

    return null;
  } catch {
    return null;
  }
}

export function buildReportUrl(report: ScanReport): string {
  return `https://haveibeenclawned.com/report?d=${encodeReport(report)}`;
}

// ── Submit Payload ──────────────────────────────────────────────────────────

export interface SubmitPayload {
  v: 3;
  s: number;
  g: Grade;
  r: CheckResult[];
}

// ── Cloudflare KV Persistence ────────────────────────────────────────────────

const KV_KEY = "haveibeenclawned:stats";

interface KVStats {
  totalScans: number;
  scoreSum: number;
  criticalCount: number;
  grades: Record<Grade, number>;
  /** Per-check fail counts (index matches CHECKS array) */
  failCounts?: number[];
}

const EMPTY_KV_STATS: KVStats = {
  totalScans: 0,
  scoreSum: 0,
  criticalCount: 0,
  grades: { A: 0, B: 0, C: 0, D: 0, F: 0 },
  failCounts: [],
};

function kvBaseUrl(): string {
  const acct = process.env.CLOUDFLARE_ACCOUNT_ID;
  const ns = process.env.CLOUDFLARE_KV_NAMESPACE_ID;
  if (!acct || !ns) throw new Error("Cloudflare KV env vars not set");
  return `https://api.cloudflare.com/client/v4/accounts/${acct}/storage/kv/namespaces/${ns}`;
}

function kvHeaders(): Record<string, string> {
  const token = process.env.CLOUDFLARE_KV_API_TOKEN;
  if (!token) throw new Error("CLOUDFLARE_KV_API_TOKEN not set");
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
}

async function kvGet(): Promise<KVStats> {
  try {
    const res = await fetch(`${kvBaseUrl()}/values/${KV_KEY}`, {
      headers: kvHeaders(),
    });
    if (!res.ok) return { ...EMPTY_KV_STATS, grades: { ...EMPTY_KV_STATS.grades } };
    const data = await res.json();
    return data as KVStats;
  } catch {
    return { ...EMPTY_KV_STATS, grades: { ...EMPTY_KV_STATS.grades } };
  }
}

async function kvPut(stats: KVStats): Promise<void> {
  await fetch(`${kvBaseUrl()}/values/${KV_KEY}`, {
    method: "PUT",
    headers: kvHeaders(),
    body: JSON.stringify(stats),
  });
}

// ── Rate Limiting (in-memory — intentional, see design doc) ─────────────────

const ipSubmissions: Map<string, number[]> = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const RATE_LIMIT_MAX = 10;

export function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const timestamps = ipSubmissions.get(ip) || [];
  const recent = timestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  ipSubmissions.set(ip, recent);
  return recent.length < RATE_LIMIT_MAX;
}

// ── Record & Stats (KV-backed) ──────────────────────────────────────────────

const NUM_CRITICAL = CHECKS.filter((c) => c.severity === "CRITICAL").length;

export async function recordSubmission(ip: string, payload: SubmitPayload): Promise<void> {
  const stats = await kvGet();

  stats.totalScans++;
  stats.scoreSum += payload.s;
  stats.grades[payload.g]++;

  // Per-check fail tracking
  if (!stats.failCounts || stats.failCounts.length === 0) {
    stats.failCounts = new Array(CHECKS.length).fill(0);
  }
  for (let i = 0; i < payload.r.length && i < CHECKS.length; i++) {
    if (payload.r[i] === 0) stats.failCounts[i]++;
  }

  const hasCriticalFail = payload.r.some(
    (r, i) => r === 0 && i < CHECKS.length && CHECKS[i].severity === "CRITICAL"
  );
  if (hasCriticalFail) stats.criticalCount++;

  await kvPut(stats);

  // Update rate limit tracking
  const timestamps = ipSubmissions.get(ip) || [];
  timestamps.push(Date.now());
  ipSubmissions.set(ip, timestamps);
}

export interface AggregateStats {
  totalScans: number;
  avgScore: number;
  criticalPct: number;
  grades: Record<Grade, number>;
  topIssues: { id: string; label: string; severity: Severity; failPct: number }[];
}

export async function getAggregateStats(): Promise<AggregateStats> {
  const stats = await kvGet();

  if (stats.totalScans === 0) {
    return {
      totalScans: 0,
      avgScore: 0,
      criticalPct: 0,
      grades: { A: 0, B: 0, C: 0, D: 0, F: 0 },
      topIssues: [],
    };
  }

  const topIssues = (stats.failCounts || [])
    .map((count, i) => ({
      id: CHECKS[i].id,
      label: CHECKS[i].label,
      severity: CHECKS[i].severity,
      failPct: Math.round((count / stats.totalScans) * 100),
    }))
    .filter((c) => c.failPct > 0)
    .sort((a, b) => b.failPct - a.failPct)
    .slice(0, 10);

  return {
    totalScans: stats.totalScans,
    avgScore: Math.round(stats.scoreSum / stats.totalScans),
    criticalPct: Math.round((stats.criticalCount / stats.totalScans) * 100),
    grades: stats.grades,
    topIssues,
  };
}
