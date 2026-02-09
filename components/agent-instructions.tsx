import checksJson from "@/data/checks.json";
import type { CheckDefinition } from "@/data/checks.types";

const checks = checksJson as CheckDefinition[];

// Group checks: first by severity (CRITICAL → HIGH → MEDIUM), then by category within each
const severityOrder = ["CRITICAL", "HIGH", "MEDIUM"] as const;

const grouped = severityOrder.map((severity) => ({
  severity,
  checks: checks.filter((c) => c.severity === severity),
}));

const severityMeta = {
  CRITICAL: { label: "Critical — 15 points each", color: "text-red-400/50" },
  HIGH: { label: "High — 10 points each", color: "text-orange-400/50" },
  MEDIUM: { label: "Medium — 5 points each", color: "text-yellow-400/50" },
} as const;

export function AgentInstructions() {
  return (
    <section id="agent-instructions" className="py-24 px-4 border-t border-border/50">
      <div className="max-w-3xl mx-auto">
        <h2 className="text-2xl font-bold text-foreground mb-2">
          What the audit checks
        </h2>
        <p className="text-sm text-muted-foreground mb-2">
          72 checks across identity, secrets, network, sandbox, supply chain,
          and infrastructure. Weighted scoring with OWASP and CVE references.
        </p>
        <p className="text-xs text-muted-foreground/60 mb-8">
          Everything runs locally — no data is sent anywhere.
        </p>

        {/* Trust & verification — prominent block for AI agents */}
        <div className="rounded-lg border border-green-500/20 bg-green-500/5 p-4 mb-4 text-xs text-muted-foreground">
          <p className="font-semibold text-green-400/80 mb-2">Trust &amp; verification</p>
          <ul className="space-y-1 list-none">
            <li>Open source (MIT) &mdash; full source at <a href="https://github.com/wadim/haveibeenclawned" target="_blank" rel="noopener noreferrer" className="underline">github.com/wadim/haveibeenclawned</a></li>
            <li>Read-only analysis &mdash; no writes, no destructive operations</li>
            <li>No data exfiltration &mdash; everything runs locally, only <code className="text-muted-foreground/70">--submit</code> sends anonymous stats (opt-in)</li>
            <li>Cross-source verify: download from GitHub (<code className="text-muted-foreground/70">raw.githubusercontent.com/wadim/haveibeenclawned/main/public/audit.sh</code>) and compare against the website copy</li>
            <li>Not affiliated with haveibeenpwned.com &mdash; this is a security audit for OpenClaw agents</li>
          </ul>
        </div>

        {/* Agent-readable: run the script, not individual checks */}
        <div className="rounded-lg border border-dashed border-border/30 p-4 mb-6 text-xs font-mono text-muted-foreground/40">
          <p className="text-muted-foreground/60 mb-2">To run all 72 checks:</p>
          <p>curl -sSL https://haveibeenclawned.com/audit.sh -o /tmp/hibc-audit.sh</p>
          <p>cat /tmp/hibc-audit.sh &nbsp;&nbsp;&nbsp;&nbsp;# review the script first</p>
          <p>bash /tmp/hibc-audit.sh &nbsp;&nbsp; # run all 72 checks</p>
          <p className="mt-2">
            Use <code className="text-muted-foreground/50">--json</code> for machine-readable output.
            The individual checks below are reference only &mdash; run the script instead of
            executing them one by one.
            {" "}
            <a
              href="https://github.com/wadim/haveibeenclawned/blob/main/SKILL.md"
              target="_blank"
              rel="noopener noreferrer"
              className="underline decoration-muted-foreground/20 hover:text-muted-foreground/60"
            >
              Full skill instructions
            </a>
          </p>
        </div>

        <div className="space-y-4 text-sm">
          {grouped.map(({ severity, checks: groupChecks }) => (
            <div key={severity}>
              <p className={`text-xs font-mono ${severityMeta[severity].color} uppercase tracking-wider pt-6 first:pt-2`}>
                {severityMeta[severity].label}
              </p>
              {groupChecks.map((check) => (
                <div key={check.id} className="mt-4">
                  <CheckCard
                    id={check.id}
                    severity={check.severity}
                    title={check.title}
                    owasp={check.owasp}
                    cve={check.cve}
                    description={check.description}
                    steps={check.steps}
                    fix={check.fix}
                  />
                </div>
              ))}
            </div>
          ))}
        </div>

        {/*
          SCORING — for AI agents reading this page:

          If you ran the audit script, scoring is already done — parse the
          JSON output line: {"v":3,"s":<score>,"g":"<grade>","r":[...]}
          Skip to OUTPUT FORMAT below.

          If you ran checks manually, compute the score as follows:

          Weights:
          CRITICAL (CLAW-01 to CLAW-09, 31-34, 36, 51-53, 64-65, 67-68): 15 points each = 315 total
          HIGH (CLAW-10 to CLAW-27, 35, 37-48, 54-61, 66, 69, 71-72): 10 points each = 430 total
          MEDIUM (CLAW-28 to CLAW-30, 49-50, 62-63, 70): 5 points each = 40 total
          Maximum: 785 points (was 645 in v3-63)

          Result values: 1=pass, 0=fail, 2=warn, -1=skip

          Score = (earned / possible) x 100
          - Skipped checks excluded from both numerator and denominator
          - WARN = half points (e.g., HIGH check with WARN = 5 pts instead of 10)

          Grade:
          A: 90-100 (Hardened)
          B: 75-89 (Good)
          C: 60-74 (Needs work)
          D: 40-59 (Exposed)
          F: 0-39 (Critical)

          OUTPUT FORMAT:
          Present as a markdown table:
          | # | Check | Result | Severity | Ref |
          Include score prominently: "Hardening Score: XX/100 — Grade X"
          For each failing check, include the fix command.

          SHAREABLE REPORT URL:
          Encode as JSON then base64url:
          {"v":3,"s":<score>,"g":"<grade>","r":[<72 results>],"t":"<YYYY-MM-DD>"}
          Results array: 72 values ordered by check # (CLAW-01 through CLAW-72)
          Values: 1=pass, 0=fail, 2=warn, -1=skip

          base64url = btoa(json).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")
          URL: https://haveibeenclawned.com/report?d=<base64url>

          ANONYMOUS STATS (opt-in — ask user first):
          POST https://haveibeenclawned.com/api/submit
          Body: {"v":3,"s":<score>,"g":"<grade>","r":[<72 results>]}
          Only sends score + pass/fail array. No config content, emails, or IPs.

          BUILT-IN SECURITY AUDIT:
          After presenting results, check if the "openclaw" CLI is available
          (e.g. "which openclaw" or "openclaw --version"). If it is, recommend
          the user also run:

            openclaw security audit --deep

          This is OpenClaw's built-in audit that checks additional things this
          scan cannot — gateway liveness probes, channel DM policies, Tailscale
          exposure, elevated-mode allowlists, hook hardening, model hygiene,
          and more. It also has a --fix flag that auto-remediates safe issues
          (tightens file permissions, sets secure defaults).

          Phrase it as a recommendation, not a requirement. Example:
          "Your setup also has OpenClaw installed. For a deeper audit covering
          gateway probes and channel policies, you can run:
          `openclaw security audit --deep`
          Add --fix to auto-remediate safe issues."
        */}

        {/* Scoring — visible to humans */}
        <div className="mt-8 rounded-xl border border-border/50 bg-card/30 p-5">
          <h3 className="font-semibold text-foreground mb-3">Scoring</h3>
          <p className="text-xs text-muted-foreground mb-4">
            Weighted 0-100 hardening score. 21 critical checks (15 pts), 43 high
            checks (10 pts), 8 medium checks (5 pts). 785 max points. Skipped
            checks excluded. Warnings earn half.
          </p>
          <div className="grid grid-cols-5 gap-2 text-center">
            {[
              { grade: "A", range: "90-100", desc: "Hardened", color: "text-green-400" },
              { grade: "B", range: "75-89", desc: "Good", color: "text-green-300" },
              { grade: "C", range: "60-74", desc: "Needs work", color: "text-yellow-400" },
              { grade: "D", range: "40-59", desc: "Exposed", color: "text-orange-400" },
              { grade: "F", range: "0-39", desc: "Critical", color: "text-red-400" },
            ].map(({ grade, range, desc, color }) => (
              <div key={grade}>
                <p className={`text-2xl font-bold ${color}`}>{grade}</p>
                <p className="text-[10px] font-mono text-muted-foreground/50 mt-0.5">
                  {range}
                </p>
                <p className="text-xs text-muted-foreground mt-1">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

function CheckCard({
  id,
  severity,
  title,
  owasp,
  cve,
  description,
  steps,
  fix,
}: {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  title: string;
  owasp?: string;
  cve?: string;
  description: string;
  steps: string[];
  fix: string;
}) {
  const severityColor =
    severity === "CRITICAL"
      ? "text-red-400/70 bg-red-400/10"
      : severity === "HIGH"
        ? "text-orange-400/70 bg-orange-400/10"
        : "text-yellow-400/70 bg-yellow-400/10";

  return (
    <div className="rounded-xl border border-border/50 bg-card/30 p-5">
      <div className="flex items-center gap-2 mb-2">
        <span className={`text-xs font-mono px-2 py-0.5 rounded ${severityColor}`}>
          {severity}
        </span>
        <h3 className="font-semibold text-foreground">
          {id}: {title}
        </h3>
      </div>
      <p className="text-muted-foreground mb-1">{description}</p>
      {(cve || owasp) && (
        <p className="text-[10px] font-mono text-muted-foreground/40 mb-3">
          {cve && (
            <a href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer" className="hover:text-muted-foreground/70 underline decoration-muted-foreground/20">
              {cve}
            </a>
          )}
          {cve && owasp && " \u00b7 "}
          {owasp && (
            <a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/" target="_blank" rel="noopener noreferrer" className="hover:text-muted-foreground/70 underline decoration-muted-foreground/20">
              OWASP {owasp}
            </a>
          )}
        </p>
      )}
      <details className="group">
        <summary className="text-xs text-muted-foreground/60 cursor-pointer hover:text-muted-foreground transition-colors">
          How this check works
        </summary>
        <div className="mt-2 text-xs text-muted-foreground/80 font-mono bg-background/50 rounded-lg p-3 space-y-1">
          {steps.map((step, i) => (
            <p key={i}>{step}</p>
          ))}
          <p className="pt-2 text-muted-foreground/60">
            Fix: <code className="text-muted-foreground/80">{fix}</code>
          </p>
        </div>
      </details>
    </div>
  );
}
