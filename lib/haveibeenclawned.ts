// Have I Been Clawned — v3: 30 checks, weighted scoring 0-100, OWASP-mapped

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

// ── Check definitions (ordered CLAW-01 through CLAW-30) ─────────────────────

export const CHECKS: CheckMeta[] = [
  // ── CRITICAL (15 pts each) ──────────────────────────────────────────────
  {
    id: "CLAW-01",
    label: "Gateway Network Exposure",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-03",
    cve: "CVE-2026-25253",
    cwe: "CWE-1327",
    atlas: "AML.T0043",
    nist: "SC-7",
    description:
      "Gateway bound to public interface — accessible from the internet",
  },
  {
    id: "CLAW-02",
    label: "Gateway Authentication",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-03",
    cve: "CVE-2026-25253",
    cwe: "CWE-306",
    atlas: "AML.T0048",
    nist: "AC-6",
    description:
      "No authentication on gateway — anyone who can reach it controls your agent",
  },
  {
    id: "CLAW-03",
    label: "Cloud Metadata Service",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-03",
    cwe: "CWE-918",
    atlas: "AML.T0043",
    nist: "SC-7",
    description:
      "Cloud metadata endpoint accessible — agent can steal IAM credentials",
  },
  {
    id: "CLAW-04",
    label: "Personal Email as Agent Identity",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-03",
    cwe: "CWE-269",
    atlas: "AML.T0052",
    nist: "IA-5",
    description:
      "Personal email used as agent identity — compromise means impersonation",
  },
  {
    id: "CLAW-05",
    label: "Plaintext API Keys in Config",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-03",
    cve: "CVE-2026-22038",
    cwe: "CWE-312",
    atlas: "AML.T0056",
    nist: "RA-5",
    description:
      "API keys in plaintext config files — any skill or process can read them",
  },
  {
    id: "CLAW-06",
    label: "Sensitive Files Accessible",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-03",
    cwe: "CWE-732",
    atlas: "AML.T0052",
    nist: "RA-5",
    description:
      "SSH keys, cloud credentials, or other sensitive files readable by agent",
  },
  {
    id: "CLAW-07",
    label: "Secrets in Session Transcripts",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-03",
    cve: "CVE-2026-22038",
    cwe: "CWE-532",
    atlas: "AML.T0056",
    nist: "RA-5",
    description:
      "API keys, credit cards, or SSNs found in conversation history files",
  },
  {
    id: "CLAW-08",
    label: "Docker Privileged Mode",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-05",
    cve: "CVE-2024-21626",
    cwe: "CWE-250",
    atlas: "AML.T0050",
    nist: "SI-7",
    description:
      "Container running with --privileged, host network, or full filesystem mount",
  },
  {
    id: "CLAW-09",
    label: "Agent Running as Root",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-05",
    cve: "CVE-2019-5736",
    cwe: "CWE-250",
    atlas: "AML.T0050",
    nist: "AC-6",
    description:
      "Agent process running as UID 0 — any compromise is full system compromise",
  },

  // ── HIGH (10 pts each) ──────────────────────────────────────────────────
  {
    id: "CLAW-10",
    label: "Sandbox Configuration",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-05",
    cwe: "CWE-693",
    atlas: "AML.T0048",
    nist: "CM-6",
    description:
      "No sandbox — agent code runs directly on host with full access",
  },
  {
    id: "CLAW-11",
    label: "Elevated Mode Restrictions",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-05",
    cve: "CVE-2026-25049",
    cwe: "CWE-250",
    atlas: "AML.T0048",
    nist: "AC-6",
    description:
      "Elevated mode unrestricted — any session can escape the sandbox",
  },
  {
    id: "CLAW-12",
    label: "Config File Permissions",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-03",
    cwe: "CWE-732",
    atlas: "AML.T0048",
    nist: "CM-6",
    description:
      "Config files readable by group or others — secrets exposed to other users",
  },
  {
    id: "CLAW-13",
    label: "Installed Skills Threat Intel",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-04",
    cve: "CVE-2025-6514",
    cwe: "CWE-1104",
    atlas: "AML.T0049",
    nist: "SI-3",
    description:
      "Known-malicious or unverified skills installed — supply chain risk",
  },
  {
    id: "CLAW-14",
    label: "MCP Server Vulnerabilities",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-04",
    cve: "CVE-2025-6514",
    cwe: "CWE-78",
    atlas: "AML.T0049",
    nist: "SI-7",
    description:
      "MCP packages with known CVEs — remote code execution risk",
  },
  {
    id: "CLAW-15",
    label: "OpenClaw Version Security",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-04",
    cwe: "CWE-1104",
    atlas: "AML.T0049",
    nist: "CM-6",
    description:
      "Running a version with known security vulnerabilities",
  },
  {
    id: "CLAW-16",
    label: "Session File Permissions",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-03",
    cwe: "CWE-538",
    atlas: "AML.T0048",
    nist: "CM-6",
    description:
      "Session files readable by others — conversation history exposed",
  },
  {
    id: "CLAW-17",
    label: "Default Credentials in Config",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-03",
    cwe: "CWE-1392",
    atlas: "AML.T0056",
    nist: "IA-5",
    description:
      "Default or placeholder values in config — unchanged from template",
  },
  {
    id: "CLAW-18",
    label: ".env Not in .gitignore",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-03",
    cwe: "CWE-538",
    atlas: "AML.T0048",
    nist: "CM-6",
    description:
      "Secret files not excluded from git — may be committed accidentally",
  },
  {
    id: "CLAW-19",
    label: "Secrets in Git History",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-03",
    cwe: "CWE-538",
    atlas: "AML.T0056",
    nist: "RA-5",
    description:
      "API keys or passwords found in git commit history — persist forever",
  },
  {
    id: "CLAW-20",
    label: "Browser Profiles Accessible",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-03",
    cve: "CVE-2025-2783",
    cwe: "CWE-732",
    atlas: "AML.T0052",
    nist: "RA-5",
    description:
      "Chrome/Firefox/Brave profiles readable — saved passwords and cookies exposed",
  },
  {
    id: "CLAW-21",
    label: "Git Credentials Accessible",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-03",
    cwe: "CWE-256",
    atlas: "AML.T0056",
    nist: "RA-5",
    description:
      "Git credential files readable — repository tokens and passwords exposed",
  },
  {
    id: "CLAW-22",
    label: "Database Credentials Accessible",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-03",
    cwe: "CWE-798",
    atlas: "AML.T0056",
    nist: "RA-5",
    description:
      "Database credential files readable — direct database access possible",
  },
  {
    id: "CLAW-23",
    label: "Additional Services on 0.0.0.0",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-03",
    cwe: "CWE-1327",
    atlas: "AML.T0043",
    nist: "SC-7",
    description:
      "Other agent services bound to all interfaces — publicly reachable",
  },
  {
    id: "CLAW-24",
    label: "No Firewall Rules",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-03",
    cwe: "CWE-284",
    atlas: "AML.T0048",
    nist: "SC-7",
    description:
      "No firewall configured — every listening port is exposed",
  },
  {
    id: "CLAW-25",
    label: "Container Security Profile",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-05",
    cve: "CVE-2025-31133",
    cwe: "CWE-250",
    atlas: "AML.T0050",
    nist: "SI-7",
    description:
      "No seccomp/AppArmor profile — container escape risk via runC CVEs",
  },
  {
    id: "CLAW-26",
    label: "Agent Code Integrity",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-04",
    cwe: "CWE-494",
    atlas: "AML.T0049",
    nist: "CM-6",
    description:
      "Uncommitted modifications to agent source — potential backdoor",
  },
  {
    id: "CLAW-27",
    label: "npm Lifecycle Scripts in Skills",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-04",
    cwe: "CWE-829",
    atlas: "AML.T0049",
    nist: "SI-7",
    description:
      "Skills with lifecycle scripts — arbitrary code runs on install",
  },

  // ── MEDIUM (5 pts each) ─────────────────────────────────────────────────
  {
    id: "CLAW-28",
    label: "Log Redaction",
    severity: "MEDIUM",
    points: 5,
    owasp: "ASI-03",
    cve: "CVE-2026-22038",
    cwe: "CWE-532",
    atlas: "AML.T0048",
    nist: "AU-2",
    description:
      "Log redaction disabled — secrets may appear in log files",
  },
  {
    id: "CLAW-29",
    label: "Debug Logging Enabled",
    severity: "MEDIUM",
    points: 5,
    owasp: "ASI-03",
    cve: "CVE-2026-22038",
    cwe: "CWE-532",
    atlas: "AML.T0048",
    nist: "AU-2",
    description:
      "Debug/verbose logging active — extra data including payloads leaked to logs",
  },
  {
    id: "CLAW-30",
    label: "Sessions Synced to Cloud",
    severity: "MEDIUM",
    points: 5,
    owasp: "ASI-03",
    cwe: "CWE-922",
    atlas: "AML.T0048",
    nist: "RA-5",
    description:
      "Session files inside cloud-synced folder — history uploaded to iCloud/Dropbox",
  },

  // ── NEW CRITICAL (15 pts each) ────────────────────────────────────────────
  {
    id: "CLAW-31",
    label: "MCP Tool Description Poisoning",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-01",
    cve: "CVE-2025-6514",
    cwe: "CWE-94",
    atlas: "AML.T0051",
    nist: "SI-3",
    description:
      "Invisible Unicode in MCP tool descriptions can hijack agent behavior",
  },
  {
    id: "CLAW-32",
    label: "MCP Tool Shadowing",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-02",
    cwe: "CWE-349",
    atlas: "AML.T0051",
    nist: "SI-3",
    description:
      "Duplicate tool names across MCP servers — malicious server intercepts calls",
  },
  {
    id: "CLAW-33",
    label: "Unrestricted Outbound Network",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-01",
    cwe: "CWE-941",
    atlas: "AML.T0043",
    nist: "SC-7",
    description:
      "No egress filtering — compromised agent can exfiltrate data to any server",
  },
  {
    id: "CLAW-34",
    label: "Messaging Platform Token Exposure",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-03",
    cwe: "CWE-522",
    atlas: "AML.T0056",
    nist: "IA-5",
    description:
      "Telegram/Slack/Discord tokens in plaintext config — full bot impersonation",
  },

  // ── NEW HIGH (10 pts each) ────────────────────────────────────────────────
  {
    id: "CLAW-35",
    label: "No User Namespace Isolation",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-05",
    cve: "CVE-2025-31133",
    cwe: "CWE-269",
    atlas: "AML.T0050",
    nist: "SI-7",
    description:
      "Container root maps to host root — container escape is full host compromise",
  },

  // ── CRITICAL (cont.) ─────────────────────────────────────────────────────
  {
    id: "CLAW-36",
    label: "Dangerous CLI Flags in Startup",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-05",
    cwe: "CWE-693",
    atlas: "AML.T0048",
    nist: "AC-6",
    description:
      "Agent started with --yolo or --dangerously-skip-permissions — zero protection",
  },

  // ── HIGH (cont.) ──────────────────────────────────────────────────────────
  {
    id: "CLAW-37",
    label: "Writable Agent Installation Directory",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-04",
    cwe: "CWE-276",
    atlas: "AML.T0048",
    nist: "CM-6",
    description:
      "Agent can modify its own code — prompt injection can install persistent backdoor",
  },
  {
    id: "CLAW-38",
    label: "No Rate Limiting on Agent API",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-03",
    cwe: "CWE-770",
    atlas: "AML.T0048",
    nist: "RA-5",
    description:
      "No rate limiting on gateway — Denial of Wallet attacks can run up LLM costs",
  },
  {
    id: "CLAW-39",
    label: "Cryptocurrency Wallet Files Accessible",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-03",
    cwe: "CWE-732",
    atlas: "AML.T0056",
    nist: "RA-5",
    description:
      "Crypto wallet files readable by agent — funds can be drained irreversibly",
  },
  {
    id: "CLAW-40",
    label: "Unsafe Deserialization in Dependencies",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-04",
    cwe: "CWE-502",
    atlas: "AML.T0052",
    nist: "RA-5",
    description:
      "Vulnerable langchain-core or unsafe yaml.load in skills — RCE via prompt injection",
  },
  {
    id: "CLAW-41",
    label: "No Container Read-Only Filesystem",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-05",
    cwe: "CWE-732",
    atlas: "AML.T0050",
    nist: "SI-7",
    description:
      "Writable container filesystem — compromised agent can install persistent malware",
  },
  {
    id: "CLAW-42",
    label: "Skill Network Access Unrestricted",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-02",
    cwe: "CWE-284",
    atlas: "AML.T0043",
    nist: "SC-7",
    description:
      "No per-skill network permissions — any skill can exfiltrate data externally",
  },
  {
    id: "CLAW-43",
    label: "Unencrypted Session Storage",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-03",
    cwe: "CWE-311",
    atlas: "AML.T0048",
    nist: "RA-5",
    description:
      "Session files stored unencrypted — disk compromise exposes full conversation history",
  },
  {
    id: "CLAW-44",
    label: "Rules File Injection",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-01",
    cwe: "CWE-94",
    atlas: "AML.T0051",
    nist: "SI-3",
    description:
      "CLAUDE.md or rules files contain invisible Unicode or suspicious injection patterns",
  },
  {
    id: "CLAW-45",
    label: "Stale or Unrotated API Keys",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-03",
    cwe: "CWE-324",
    atlas: "AML.T0056",
    nist: "IA-5",
    description:
      "Credential files not modified in 90+ days — extended window for stolen key abuse",
  },
  {
    id: "CLAW-46",
    label: "npm Audit Vulnerabilities",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-04",
    cwe: "CWE-1104",
    atlas: "AML.T0049",
    nist: "SI-7",
    description:
      "Known vulnerabilities in agent npm dependencies — supply chain risk",
  },
  {
    id: "CLAW-47",
    label: "Excessive Tool Permissions",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-02",
    cwe: "CWE-250",
    atlas: "AML.T0048",
    nist: "AC-6",
    description:
      "Wildcard tool permissions — agent can write anywhere, execute anything",
  },
  {
    id: "CLAW-48",
    label: "Insecure MCP Transport",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-07",
    cwe: "CWE-319",
    atlas: "AML.T0043",
    nist: "SC-7",
    description:
      "Remote MCP servers connected via HTTP — tool data transmitted in cleartext",
  },

  // ── NEW MEDIUM (5 pts each) ───────────────────────────────────────────────
  {
    id: "CLAW-49",
    label: "No Process Resource Limits",
    severity: "MEDIUM",
    points: 5,
    owasp: "ASI-05",
    cwe: "CWE-400",
    atlas: "AML.T0050",
    nist: "SI-7",
    description:
      "No ulimits or cgroup limits — runaway agent can exhaust all host resources",
  },
  {
    id: "CLAW-50",
    label: "Exposed Health/Debug Endpoints",
    severity: "MEDIUM",
    points: 5,
    owasp: "ASI-03",
    cwe: "CWE-215",
    atlas: "AML.T0048",
    nist: "AU-2",
    description:
      "Debug or config endpoints return 200 — internal state leaked to attackers",
  },

  // ── NEW CRITICAL (15 pts each) ────────────────────────────────────────────
  {
    id: "CLAW-51",
    label: "WebSocket Origin Validation (CSWSH)",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-03",
    cwe: "CWE-346",
    atlas: "AML.T0043",
    nist: "SC-7",
    description:
      "Gateway accepts WebSocket connections from any origin — cross-site hijacking possible",
  },
  {
    id: "CLAW-52",
    label: "LLM Endpoint Integrity",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-01",
    cwe: "CWE-345",
    atlas: "AML.T0048",
    nist: "RA-5",
    description:
      "API base URLs in config do not match expected providers — possible man-in-the-middle",
  },
  {
    id: "CLAW-53",
    label: "Credential Routing Through LLM Context",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-03",
    cwe: "CWE-522",
    atlas: "AML.T0056",
    nist: "RA-5",
    description:
      "Skill instructions route secrets through the LLM prompt — credentials exposed in context window",
  },

  // ── NEW HIGH (10 pts each) ──────────────────────────────────────────────
  {
    id: "CLAW-54",
    label: "Persistent Memory Poisoning",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-06",
    cwe: "CWE-94",
    atlas: "AML.T0051",
    nist: "SI-3",
    description:
      "Injection markers found in memory or context files — persistent prompt injection risk",
  },
  {
    id: "CLAW-55",
    label: "Auto-Approval Beyond --yolo",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-02",
    cwe: "CWE-863",
    atlas: "AML.T0048",
    nist: "AC-6",
    description:
      "Per-category auto-approve or allowedTools wildcards bypass tool confirmation",
  },
  {
    id: "CLAW-56",
    label: "Semantic Tool Description Poisoning",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-01",
    cve: "CVE-2025-6514",
    cwe: "CWE-94",
    atlas: "AML.T0051",
    nist: "SI-3",
    description:
      "MCP tool descriptions contain exfiltration instructions or data harvesting patterns",
  },
  {
    id: "CLAW-57",
    label: "Tool Definition Pinning (Rug-Pull)",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-04",
    cwe: "CWE-494",
    atlas: "AML.T0049",
    nist: "SI-7",
    description:
      "No integrity check on tool definitions — server can change tool behavior after approval",
  },
  {
    id: "CLAW-58",
    label: "MCP Credential Hygiene",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-03",
    cwe: "CWE-522",
    atlas: "AML.T0056",
    nist: "IA-5",
    description:
      "MCP servers use long-lived PATs instead of short-lived OAuth tokens",
  },
  {
    id: "CLAW-59",
    label: "Dormant Payload Detection",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-01",
    cwe: "CWE-506",
    atlas: "AML.T0051",
    nist: "SI-3",
    description:
      "Conditional or time-based triggers found in persistent context — delayed attack risk",
  },
  {
    id: "CLAW-60",
    label: "Observability Endpoint Security",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-10",
    cwe: "CWE-319",
    atlas: "AML.T0043",
    nist: "AU-2",
    description:
      "Telemetry endpoints use HTTP or have known CVEs — trace data exposed",
  },
  {
    id: "CLAW-61",
    label: "Skill Typosquatting Detection",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-04",
    cwe: "CWE-426",
    atlas: "AML.T0049",
    nist: "SI-3",
    description:
      "Installed skill name is suspiciously similar to a popular skill — possible typosquatting",
  },

  // ── NEW MEDIUM (5 pts each) ─────────────────────────────────────────────
  {
    id: "CLAW-62",
    label: "Sandbox Runtime Detection",
    severity: "MEDIUM",
    points: 5,
    owasp: "ASI-05",
    cwe: "CWE-693",
    atlas: "AML.T0050",
    nist: "SI-7",
    description:
      "Container uses default runc runtime — weaker isolation than gVisor or Firecracker",
  },
  {
    id: "CLAW-63",
    label: "Writable Persistence Paths",
    severity: "MEDIUM",
    points: 5,
    owasp: "ASI-05",
    cwe: "CWE-276",
    atlas: "AML.T0048",
    nist: "SI-3",
    description:
      "Agent can write to crontab, shell configs, or launch agents — persistence vector for injected payloads",
  },

  // ── NEW CRITICAL (15 pts each) ────────────────────────────────────────────
  {
    id: "CLAW-64",
    label: "Active C2 Connection Detection",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-03",
    description:
      "Check active network connections against known C2 infrastructure IPs from the ClawHavoc campaign.",
  },
  {
    id: "CLAW-65",
    label: "Malware Signature Scan",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-04",
    cwe: "CWE-506",
    description:
      "Scan installed skills for AMOS stealer patterns, reverse shell markers, and known malicious file hashes.",
  },
  {
    id: "CLAW-67",
    label: "VS Code Extension Trojans",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-04",
    cwe: "CWE-506",
    description:
      "Detect fake OpenClaw VS Code extensions — OpenClaw has no official extension, so any match is malicious.",
  },
  {
    id: "CLAW-68",
    label: "Gateway Device Auth Bypass",
    severity: "CRITICAL",
    points: 15,
    owasp: "ASI-03",
    description:
      "Check if dangerouslyDisableDeviceAuth is enabled or if LAN-bound gateway lacks trustedProxies config.",
  },

  // ── NEW HIGH (10 pts each) ──────────────────────────────────────────────
  {
    id: "CLAW-66",
    label: "Exfiltration Domain References",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-04",
    cwe: "CWE-200",
    description:
      "Check skill files for references to known exfiltration services (webhook.site, pipedream.net, ngrok.io, etc.).",
  },
  {
    id: "CLAW-69",
    label: "Exec-Approvals Hardening",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-05",
    description:
      "Verify exec-approvals.json doesn't have allow-all security settings or disabled confirmation prompts.",
  },
  {
    id: "CLAW-71",
    label: "DM Channel Restrictions",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-03",
    description:
      "Check messaging channel DM policies for open access — channels with dmPolicy='open' or wildcard allowFrom let anyone message the agent.",
  },
  {
    id: "CLAW-72",
    label: "Known Malicious Publishers",
    severity: "HIGH",
    points: 10,
    owasp: "ASI-04",
    cwe: "CWE-506",
    description:
      "Check installed skill package.json files against a blacklist of known malicious ClawHub publishers.",
  },

  // ── NEW MEDIUM (5 pts each) ─────────────────────────────────────────────
  {
    id: "CLAW-70",
    label: "mDNS/Bonjour Exposure",
    severity: "MEDIUM",
    points: 5,
    owasp: "ASI-03",
    description:
      "Check if mDNS broadcasting is in 'full' mode, which exposes file paths and SSH ports to the local network.",
  },
];

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
}

const EMPTY_KV_STATS: KVStats = {
  totalScans: 0,
  scoreSum: 0,
  criticalCount: 0,
  grades: { A: 0, B: 0, C: 0, D: 0, F: 0 },
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
}

export async function getAggregateStats(): Promise<AggregateStats> {
  const stats = await kvGet();

  if (stats.totalScans === 0) {
    return {
      totalScans: 0,
      avgScore: 0,
      criticalPct: 0,
      grades: { A: 0, B: 0, C: 0, D: 0, F: 0 },
    };
  }

  return {
    totalScans: stats.totalScans,
    avgScore: Math.round(stats.scoreSum / stats.totalScans),
    criticalPct: Math.round((stats.criticalCount / stats.totalScans) * 100),
    grades: stats.grades,
  };
}
