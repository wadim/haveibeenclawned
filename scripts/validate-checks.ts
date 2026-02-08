#!/usr/bin/env npx tsx
/**
 * Validates that audit.sh, SKILL.md, and data/checks.json are consistent.
 *
 * Checks:
 *   1. Sequential ordering: CLAW-01 at index 0 through CLAW-72 at index 71
 *   2. Points–severity consistency: CRITICAL=15, HIGH=10, MEDIUM=5
 *   3. audit.sh CHECK_POINTS matches JSON points
 *   4. audit.sh CHECK_LABELS matches JSON titles
 *   5. audit.sh CHECK_CATEGORIES matches JSON categories
 *   6. SKILL.md check IDs and titles match JSON
 *   7. MAX_POINTS = 785
 *
 * Exit code 1 on any error.
 */

import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, "..");

interface CheckDef {
  id: string;
  title: string;
  severity: string;
  points: number;
  category: string;
}

const checks: CheckDef[] = JSON.parse(
  readFileSync(resolve(root, "data/checks.json"), "utf8")
);

let errors = 0;

function fail(msg: string) {
  console.error(`  ERROR: ${msg}`);
  errors++;
}

function warn(msg: string) {
  console.warn(`  WARN: ${msg}`);
}

// ── 1. Sequential ordering ─────────────────────────────────────────────────

console.log("Checking sequential ordering...");
for (let i = 0; i < checks.length; i++) {
  const expected = `CLAW-${String(i + 1).padStart(2, "0")}`;
  if (checks[i].id !== expected) {
    fail(`Index ${i}: expected ${expected}, got ${checks[i].id}`);
  }
}

// ── 2. Points–severity consistency ─────────────────────────────────────────

console.log("Checking points-severity consistency...");
const expectedPoints: Record<string, number> = {
  CRITICAL: 15,
  HIGH: 10,
  MEDIUM: 5,
};
for (const c of checks) {
  if (expectedPoints[c.severity] !== c.points) {
    fail(`${c.id}: severity ${c.severity} should be ${expectedPoints[c.severity]} pts, got ${c.points}`);
  }
}

// ── 3. MAX_POINTS ──────────────────────────────────────────────────────────

console.log("Checking MAX_POINTS...");
const maxPoints = checks.reduce((s, c) => s + c.points, 0);
if (maxPoints !== 785) {
  fail(`MAX_POINTS = ${maxPoints}, expected 785`);
}

// ── 4. audit.sh arrays ─────────────────────────────────────────────────────

console.log("Checking audit.sh arrays...");
const auditSrc = readFileSync(resolve(root, "audit.sh"), "utf8");

/**
 * Extract a bash array by finding its opening `(` and matching closing `)`.
 * Handles parentheses inside quoted strings (e.g. "(CSWSH)").
 */
function extractBashArray(name: string): string | null {
  const start = auditSrc.indexOf(`${name}=(`);
  if (start === -1) return null;
  const openParen = auditSrc.indexOf("(", start);
  let depth = 0;
  let inQuote = false;
  for (let i = openParen; i < auditSrc.length; i++) {
    const ch = auditSrc[i];
    if (ch === '"' && auditSrc[i - 1] !== "\\") inQuote = !inQuote;
    if (!inQuote) {
      if (ch === "(") depth++;
      if (ch === ")") {
        depth--;
        if (depth === 0) return auditSrc.slice(openParen + 1, i);
      }
    }
  }
  return null;
}

// Extract CHECK_POINTS
const pointsStr = extractBashArray("CHECK_POINTS");
if (!pointsStr) {
  fail("Could not find CHECK_POINTS in audit.sh");
} else {
  const auditPoints = pointsStr.trim().split(/\s+/).filter(s => /^\d+$/.test(s)).map(Number);
  if (auditPoints.length !== checks.length) {
    fail(`CHECK_POINTS has ${auditPoints.length} entries, expected ${checks.length}`);
  } else {
    for (let i = 0; i < checks.length; i++) {
      if (auditPoints[i] !== checks[i].points) {
        fail(`CHECK_POINTS[${i}] (${checks[i].id}): ${auditPoints[i]} != ${checks[i].points}`);
      }
    }
  }
}

// Extract CHECK_LABELS
const labelsStr = extractBashArray("CHECK_LABELS");
if (!labelsStr) {
  fail("Could not find CHECK_LABELS in audit.sh");
} else {
  const auditLabels = [...labelsStr.matchAll(/"([^"]*?)"/g)].map((m) => m[1]);
  if (auditLabels.length !== checks.length) {
    fail(`CHECK_LABELS has ${auditLabels.length} entries, expected ${checks.length}`);
  } else {
    for (let i = 0; i < checks.length; i++) {
      if (auditLabels[i] !== checks[i].title) {
        fail(`CHECK_LABELS[${i}] (${checks[i].id}): "${auditLabels[i]}" != "${checks[i].title}"`);
      }
    }
  }
}

// Extract CHECK_CATEGORIES
const catsStr = extractBashArray("CHECK_CATEGORIES");
if (!catsStr) {
  fail("Could not find CHECK_CATEGORIES in audit.sh");
} else {
  const auditCats = catsStr.trim().split(/\s+/).filter(s => s && !s.startsWith("#"));
  if (auditCats.length !== checks.length) {
    fail(`CHECK_CATEGORIES has ${auditCats.length} entries, expected ${checks.length}`);
  } else {
    for (let i = 0; i < checks.length; i++) {
      if (auditCats[i] !== checks[i].category) {
        fail(`CHECK_CATEGORIES[${i}] (${checks[i].id}): "${auditCats[i]}" != "${checks[i].category}"`);
      }
    }
  }
}

// ── 5. SKILL.md check IDs and titles ───────────────────────────────────────

console.log("Checking SKILL.md...");
try {
  const skillSrc = readFileSync(resolve(root, "SKILL.md"), "utf8");
  const jsonMap = new Map(checks.map((c) => [c.id, c]));

  // Find all CLAW-XX references in SKILL.md
  const idMatches = [...skillSrc.matchAll(/\b(CLAW-\d+)\b/g)];
  const skillIds = new Set(idMatches.map((m) => m[1]));

  // Check that every JSON check ID appears in SKILL.md
  for (const c of checks) {
    if (!skillIds.has(c.id)) {
      warn(`${c.id} not found in SKILL.md`);
    }
  }

  // Check for unknown IDs in SKILL.md
  for (const id of skillIds) {
    if (!jsonMap.has(id)) {
      fail(`SKILL.md references unknown check ${id}`);
    }
  }

  // Check titles where we can find "CLAW-XX: Title" or "CLAW-XX — Title" patterns
  const titleMatches = [
    ...skillSrc.matchAll(/\b(CLAW-\d+)[:\s—–-]+([^\n|*]+)/g),
  ];
  for (const m of titleMatches) {
    const id = m[1];
    const title = m[2].trim().replace(/\s*\|.*/, "").replace(/\*+$/, "").trim();
    const check = jsonMap.get(id);
    if (check && title.length > 5 && !check.title.startsWith(title.slice(0, 10))) {
      // Fuzzy check — SKILL.md titles may be truncated
      if (title !== check.title && !check.title.includes(title) && !title.includes(check.title)) {
        warn(`${id} title mismatch in SKILL.md: "${title}" vs "${check.title}"`);
      }
    }
  }
} catch {
  warn("Could not read SKILL.md — skipping SKILL.md validation");
}

// ── 6. Check count ─────────────────────────────────────────────────────────

console.log("Checking count...");
if (checks.length !== 72) {
  fail(`Expected 72 checks, got ${checks.length}`);
}

// ── Summary ────────────────────────────────────────────────────────────────

console.log("");
if (errors > 0) {
  console.error(`FAILED: ${errors} error(s) found`);
  process.exit(1);
} else {
  console.log("PASSED: All checks consistent");
  console.log(`  ${checks.length} checks, MAX_POINTS=${maxPoints}`);
  const crit = checks.filter((c) => c.severity === "CRITICAL").length;
  const high = checks.filter((c) => c.severity === "HIGH").length;
  const med = checks.filter((c) => c.severity === "MEDIUM").length;
  console.log(`  CRITICAL: ${crit}, HIGH: ${high}, MEDIUM: ${med}`);
}
