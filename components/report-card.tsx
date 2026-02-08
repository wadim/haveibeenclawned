"use client";

import { useState } from "react";
import Link from "next/link";
import type { ScanReport, CheckResult } from "@/lib/haveibeenclawned";
import { CHECKS } from "@/lib/haveibeenclawned";

const GRADE_COLORS: Record<string, string> = {
  A: "text-green-400 border-green-400/30 bg-green-400/5",
  B: "text-green-300 border-green-300/30 bg-green-300/5",
  C: "text-yellow-400 border-yellow-400/30 bg-yellow-400/5",
  D: "text-orange-400 border-orange-400/30 bg-orange-400/5",
  F: "text-red-400 border-red-400/30 bg-red-400/5",
};

const GRADE_LABELS: Record<string, string> = {
  A: "Hardened",
  B: "Good",
  C: "Needs work",
  D: "Exposed",
  F: "Critical",
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "text-red-400/70 bg-red-400/10",
  HIGH: "text-orange-400/70 bg-orange-400/10",
  MEDIUM: "text-yellow-400/70 bg-yellow-400/10",
};

function getResultDisplay(result: CheckResult) {
  switch (result) {
    case 1:
      return { icon: "\u2713", label: "PASS", color: "text-green-400" };
    case 0:
      return { icon: "\u2717", label: "FAIL", color: "text-red-400" };
    case 2:
      return { icon: "!", label: "WARN", color: "text-yellow-400" };
    default:
      return {
        icon: "\u2014",
        label: "SKIP",
        color: "text-muted-foreground/50",
      };
  }
}

export function ReportCard({ report }: { report: ScanReport }) {
  const [copied, setCopied] = useState(false);
  const gradeColor = GRADE_COLORS[report.g] || GRADE_COLORS.F;

  const scoreBarColor =
    report.s >= 90
      ? "bg-green-400"
      : report.s >= 75
        ? "bg-green-300"
        : report.s >= 60
          ? "bg-yellow-400"
          : report.s >= 40
            ? "bg-orange-400"
            : "bg-red-400";

  const handleCopy = async () => {
    const url = window.location.href;
    await navigator.clipboard.writeText(url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const failCount = report.r.filter((r) => r === 0).length;
  const warnCount = report.r.filter((r) => r === 2).length;
  const passCount = report.r.filter((r) => r === 1).length;
  const skipCount = report.r.filter((r) => r === -1).length;

  return (
    <div className="max-w-2xl mx-auto">
      {/* Score + Grade */}
      <div className={`rounded-2xl border ${gradeColor} p-8 text-center mb-8`}>
        <p className="text-sm text-muted-foreground mb-2 font-mono">
          Hardening Score
        </p>
        <div className="flex items-baseline justify-center gap-3 mb-3">
          <p className="text-6xl md:text-7xl font-bold tracking-tighter">
            {report.s}
          </p>
          <p className="text-2xl text-muted-foreground/50">/100</p>
        </div>
        {/* Score bar */}
        <div className="w-full max-w-xs mx-auto h-2 rounded-full bg-border/30 mb-4">
          <div
            className={`h-full rounded-full ${scoreBarColor} transition-all`}
            style={{ width: `${report.s}%` }}
          />
        </div>
        <p className="text-4xl font-bold mb-1">Grade {report.g}</p>
        <p className="text-lg text-muted-foreground">
          {GRADE_LABELS[report.g]}
        </p>
      </div>

      {/* Summary strip */}
      <div className="flex justify-center gap-6 mb-6 text-sm font-mono">
        <span className="text-green-400">{passCount} passed</span>
        {warnCount > 0 && (
          <span className="text-yellow-400">{warnCount} warned</span>
        )}
        <span className="text-red-400">{failCount} failed</span>
        {skipCount > 0 && (
          <span className="text-muted-foreground/50">{skipCount} skipped</span>
        )}
      </div>

      {/* Check results */}
      <div className="rounded-2xl border border-border/50 bg-card/30 divide-y divide-border/30">
        {CHECKS.map((check, i) => {
          const result = report.r[i];
          const display = getResultDisplay(result);

          return (
            <div key={check.id} className="flex items-center gap-3 px-5 py-3">
              <div
                className={`flex-shrink-0 w-5 text-center text-lg ${display.color}`}
              >
                {display.icon}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-muted-foreground/40">
                    {check.id}
                  </span>
                  <p className="text-sm font-medium text-foreground truncate">
                    {check.label}
                  </p>
                </div>
                {(check.cve || check.owasp || check.cwe) && (
                  <p className="text-[10px] font-mono text-muted-foreground/30 mt-0.5">
                    {check.cve && (
                      <a href={`https://nvd.nist.gov/vuln/detail/${check.cve}`} target="_blank" rel="noopener noreferrer" className="hover:text-muted-foreground/50 underline decoration-muted-foreground/15">
                        {check.cve}
                      </a>
                    )}
                    {check.cve && check.owasp && " \u00b7 "}
                    {check.owasp && (
                      <a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/" target="_blank" rel="noopener noreferrer" className="hover:text-muted-foreground/50 underline decoration-muted-foreground/15">
                        OWASP {check.owasp}
                      </a>
                    )}
                    {(check.cve || check.owasp) && check.cwe && " \u00b7 "}
                    {check.cwe && (
                      <a href={`https://cwe.mitre.org/data/definitions/${check.cwe.replace("CWE-", "")}.html`} target="_blank" rel="noopener noreferrer" className="hover:text-muted-foreground/50 underline decoration-muted-foreground/15">
                        {check.cwe}
                      </a>
                    )}
                  </p>
                )}
              </div>
              <span
                className={`flex-shrink-0 text-[10px] font-mono px-2 py-0.5 rounded ${
                  SEVERITY_COLORS[check.severity] || ""
                }`}
              >
                {check.severity}
              </span>
            </div>
          );
        })}
      </div>

      {/* Scanned at */}
      <p className="text-xs text-muted-foreground/50 text-center mt-4 font-mono">
        Scanned{" "}
        {new Date(report.t).toLocaleDateString("en-US", {
          year: "numeric",
          month: "long",
          day: "numeric",
        })}
      </p>

      {/* Actions */}
      <div className="flex flex-col sm:flex-row gap-3 mt-8">
        <button
          onClick={handleCopy}
          className="flex-1 px-4 py-3 rounded-xl border border-border/50 bg-card/30 text-sm font-medium text-foreground hover:bg-card/50 transition-colors"
        >
          {copied ? "Copied!" : "Copy link to share"}
        </button>
        <Link
          href="/"
          className="flex-1 px-4 py-3 rounded-xl bg-foreground text-background text-sm font-semibold text-center hover:bg-foreground/90 transition-colors"
        >
          Run your own audit
        </Link>
      </div>
    </div>
  );
}
