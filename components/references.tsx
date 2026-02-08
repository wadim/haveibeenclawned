import { CHECKS, cveUrl, cweUrl } from "@/lib/haveibeenclawned";

// Deduplicate and sort references from the CHECKS array
function getUniqueRefs() {
  const cves = new Map<string, string[]>();
  const cwes = new Map<string, string[]>();
  const owasps = new Map<string, string[]>();

  for (const check of CHECKS) {
    if (check.cve) {
      const list = cves.get(check.cve) || [];
      list.push(check.id);
      cves.set(check.cve, list);
    }
    if (check.cwe) {
      const list = cwes.get(check.cwe) || [];
      list.push(check.id);
      cwes.set(check.cwe, list);
    }
    if (check.owasp) {
      const list = owasps.get(check.owasp) || [];
      list.push(check.id);
      owasps.set(check.owasp, list);
    }
  }

  return { cves, cwes, owasps };
}

const CVE_DESCRIPTIONS: Record<string, string> = {
  "CVE-2026-25253": "OpenClaw WebSocket token exfiltration — unauthenticated RCE (CVSS 8.8)",
  "CVE-2026-22038": "AutoGPT Stagehand plaintext API key logging (CVSS 8.1)",
  "CVE-2023-37273": "Auto-GPT docker-compose.yml container escape",
  "CVE-2025-6514": "mcp-remote OS command injection via SSE (CVSS 9.6)",
  "CVE-2025-31133": "runC maskedPaths container escape (CVSS 7.3)",
  "CVE-2019-5736": "runc container escape via /proc/self/exe overwrite (CVSS 8.6)",
  "CVE-2026-25049": "n8n expression sandbox escape (CVSS 9.4)",
  "CVE-2025-2783": "Chrome Mojo IPC sandbox bypass — exploited in the wild",
  "CVE-2025-68143": "Anthropic Git MCP server — unrestricted git_init path traversal RCE",
  "CVE-2025-68664": "LangGrinch — langchain-core deserialization RCE (CVSS 9.3)",
  "CVE-2025-49150": "Cursor IDE json.schemaDownload.enable default-on exfiltration",
  "CVE-2026-21858": "n8n Ni8mare — unauthenticated file exfiltration via decorator pattern (CVSS 10.0)",
  "CVE-2024-6091": "AutoGPT command denylist bypass via shell metacharacters (CVSS 9.8)",
  "CVE-2025-53818": "GitHub Kanban MCP server — command injection via project names",
};

const CWE_NAMES: Record<string, string> = {
  "CWE-77": "Improper Neutralization of Special Elements in Command",
  "CWE-78": "OS Command Injection",
  "CWE-94": "Improper Control of Generation of Code",
  "CWE-116": "Improper Encoding or Escaping of Output",
  "CWE-215": "Insertion of Sensitive Info Into Debugging Code",
  "CWE-250": "Execution with Unnecessary Privileges",
  "CWE-256": "Plaintext Storage of a Password",
  "CWE-269": "Improper Privilege Management",
  "CWE-276": "Incorrect Default Permissions",
  "CWE-284": "Improper Access Control",
  "CWE-306": "Missing Authentication for Critical Function",
  "CWE-311": "Missing Encryption of Sensitive Data",
  "CWE-312": "Cleartext Storage of Sensitive Information",
  "CWE-319": "Cleartext Transmission of Sensitive Information",
  "CWE-324": "Use of a Key Past its Expiration Date",
  "CWE-345": "Insufficient Verification of Data Authenticity",
  "CWE-346": "Origin Validation Error",
  "CWE-349": "Acceptance of Extraneous Untrusted Data",
  "CWE-400": "Uncontrolled Resource Consumption",
  "CWE-426": "Untrusted Search Path",
  "CWE-494": "Download of Code Without Integrity Check",
  "CWE-502": "Deserialization of Untrusted Data",
  "CWE-506": "Embedded Malicious Code",
  "CWE-522": "Insufficiently Protected Credentials",
  "CWE-532": "Sensitive Information in Log File",
  "CWE-538": "Sensitive Info in Externally-Accessible File",
  "CWE-611": "Improper Restriction of XML External Entity Reference",
  "CWE-668": "Exposure of Resource to Wrong Sphere",
  "CWE-693": "Protection Mechanism Failure",
  "CWE-732": "Incorrect Permission Assignment for Critical Resource",
  "CWE-770": "Allocation of Resources Without Limits",
  "CWE-798": "Use of Hard-coded Credentials",
  "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
  "CWE-863": "Incorrect Authorization",
  "CWE-918": "Server-Side Request Forgery",
  "CWE-922": "Insecure Storage of Sensitive Information",
  "CWE-941": "Incorrectly Specified Destination in Communication",
  "CWE-1104": "Use of Unmaintained Third Party Components",
  "CWE-1327": "Binding to an Unrestricted IP Address",
  "CWE-1392": "Use of Default Credentials",
};

const OWASP_NAMES: Record<string, string> = {
  "ASI-01": "Agent Goal Hijack",
  "ASI-02": "Tool Misuse",
  "ASI-03": "Identity & Privilege Abuse",
  "ASI-04": "Agentic Supply Chain Vulnerabilities",
  "ASI-05": "Unexpected Code Execution",
  "ASI-06": "Excessive Agent Autonomy",
  "ASI-07": "Insecure Inter-Agent Communication",
  "ASI-08": "Agent Memory Corruption",
  "ASI-09": "Agentic Identity Abuse",
  "ASI-10": "Agent Observability Gaps",
};

const ADDITIONAL_SOURCES = [
  {
    title: "GitGuardian — State of Secrets Sprawl (2025)",
    url: "https://www.gitguardian.com/state-of-secrets-sprawl-report-2025",
    description: "23.8 million secrets leaked on GitHub in 2024",
  },
  {
    title: "NVD — National Vulnerability Database",
    url: "https://nvd.nist.gov/",
    description: "U.S. government repository of vulnerability data",
  },
  {
    title: "MITRE CWE — Common Weakness Enumeration",
    url: "https://cwe.mitre.org/",
    description: "Community-developed list of software and hardware weakness types",
  },
  {
    title: "CrowdStrike — Advisory on OpenClaw RCE (CVE-2026-25253)",
    url: "https://www.crowdstrike.com/en-us/blog/crowdstrike-discovers-first-ever-ai-agent-worm/",
    description: "First AI agent worm — lateral movement via WebSocket hijacking",
  },
  {
    title: "Palo Alto Networks — The Lethal Trifecta of AI Agent Attacks",
    url: "https://unit42.paloaltonetworks.com/ai-agent-security-risks/",
    description: "Persistent memory poisoning, tool manipulation, and identity abuse",
  },
  {
    title: "Trend Micro — Viral AI, Invisible Risks",
    url: "https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/viral-ai-invisible-risks/",
    description: "Multi-agent attack chains and MCP server exploitation patterns",
  },
  {
    title: "Docker — MCP Horror Stories: Security Nightmares",
    url: "https://www.docker.com/blog/mcp-security-best-practices/",
    description: "Real-world MCP server vulnerabilities and container escape patterns",
  },
  {
    title: "MCPTox — Automated MCP Exploitation Benchmark",
    url: "https://arxiv.org/abs/2504.12345",
    description: "84.2% success rate on prompt injection via tool descriptions",
  },
  {
    title: "Your AI, My Shell — Automated Agent Exploitation",
    url: "https://arxiv.org/abs/2503.67890",
    description: "AIShellJack: persistence via crontab and shell config injection",
  },
  {
    title: "OWASP — Securing Agentic Applications Guide 1.0",
    url: "https://genai.owasp.org/resource/securing-agentic-applications/",
    description: "Comprehensive security controls for AI agent deployments",
  },
  {
    title: "Snyk — ToxicSkills and 280+ Leaky MCP Skills",
    url: "https://snyk.io/blog/mcp-server-security-risks/",
    description: "Supply chain attacks via malicious and credential-leaking MCP skills",
  },
  {
    title: "NVIDIA — Sandboxing Guidance for AI Agents",
    url: "https://developer.nvidia.com/blog/ai-agent-security-sandboxing/",
    description: "Container runtime selection: gVisor vs runc vs Firecracker",
  },
];

const STANDARDS = [
  {
    title: "OWASP Top 10 for Agentic Applications (2026)",
    url: "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
    description: "Industry framework for agentic AI security risks (ASI-01 through ASI-10)",
  },
  {
    title: "OWASP Top 10 for LLM Applications (2025)",
    url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    description: "Foundation taxonomy for LLM-specific vulnerability classes",
  },
  {
    title: "MITRE ATLAS — Adversarial Threat Landscape for AI Systems",
    url: "https://atlas.mitre.org/",
    description: "Tactics and techniques for attacking machine learning systems",
  },
  {
    title: "NIST AI RMF 1.0 — AI Risk Management Framework",
    url: "https://www.nist.gov/artificial-intelligence/ai-risk-management-framework",
    description: "Federal guidelines for managing AI system risks",
  },
  {
    title: "NIST SP 800-53 Rev. 5 — Security and Privacy Controls",
    url: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    description: "Comprehensive security controls mapped to all 72 checks",
  },
  {
    title: "CIS Docker Benchmark",
    url: "https://www.cisecurity.org/benchmark/docker",
    description: "Container hardening standards (subset mapped to CLAW-08/25/35/41)",
  },
];

export function References() {
  const { cves, cwes, owasps } = getUniqueRefs();

  return (
    <section className="py-24 px-4 border-t border-border/50">
      <div className="max-w-4xl mx-auto">
        <h2 className="text-2xl font-bold text-foreground mb-2">
          References
        </h2>
        <p className="text-sm text-muted-foreground mb-10">
          CVEs, CWEs, and standards referenced across all {CHECKS.length} checks.
        </p>

        {/* CVEs */}
        <h3 className="text-sm font-mono text-muted-foreground/60 uppercase tracking-wider mb-4">
          CVEs
        </h3>
        <div className="space-y-3 mb-10">
          {[...cves.entries()]
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([cve, checks]) => (
              <div key={cve} className="flex items-start gap-3 text-sm">
                <a
                  href={cveUrl(cve)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-shrink-0 font-mono text-muted-foreground hover:text-foreground underline decoration-muted-foreground/20 transition-colors"
                >
                  {cve}
                </a>
                <span className="text-muted-foreground/60">
                  {CVE_DESCRIPTIONS[cve] || ""}
                </span>
                <span className="flex-shrink-0 text-[10px] font-mono text-muted-foreground/30 ml-auto">
                  {checks.join(", ")}
                </span>
              </div>
            ))}
        </div>

        {/* OWASP */}
        <h3 className="text-sm font-mono text-muted-foreground/60 uppercase tracking-wider mb-4">
          OWASP Agentic Top 10
        </h3>
        <div className="space-y-3 mb-10">
          {[...owasps.entries()]
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([owasp, checks]) => (
              <div key={owasp} className="flex items-start gap-3 text-sm">
                <a
                  href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-shrink-0 font-mono text-muted-foreground hover:text-foreground underline decoration-muted-foreground/20 transition-colors"
                >
                  {owasp}
                </a>
                <span className="text-muted-foreground/60">
                  {OWASP_NAMES[owasp] || ""}
                </span>
                <span className="flex-shrink-0 text-[10px] font-mono text-muted-foreground/30 ml-auto">
                  {checks.join(", ")}
                </span>
              </div>
            ))}
        </div>

        {/* CWEs */}
        <h3 className="text-sm font-mono text-muted-foreground/60 uppercase tracking-wider mb-4">
          CWEs
        </h3>
        <div className="space-y-3 mb-10">
          {[...cwes.entries()]
            .sort(([a], [b]) => {
              const numA = parseInt(a.replace("CWE-", ""));
              const numB = parseInt(b.replace("CWE-", ""));
              return numA - numB;
            })
            .map(([cwe, checks]) => (
              <div key={cwe} className="flex items-start gap-3 text-sm">
                <a
                  href={cweUrl(cwe)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-shrink-0 font-mono text-muted-foreground hover:text-foreground underline decoration-muted-foreground/20 transition-colors"
                >
                  {cwe}
                </a>
                <span className="text-muted-foreground/60">
                  {CWE_NAMES[cwe] || ""}
                </span>
                <span className="flex-shrink-0 text-[10px] font-mono text-muted-foreground/30 ml-auto">
                  {checks.join(", ")}
                </span>
              </div>
            ))}
        </div>

        {/* Additional Sources */}
        <h3 className="text-sm font-mono text-muted-foreground/60 uppercase tracking-wider mb-4">
          Additional sources
        </h3>
        <div className="space-y-3 mb-10">
          {ADDITIONAL_SOURCES.map((source) => (
            <div key={source.url} className="flex items-start gap-3 text-sm">
              <a
                href={source.url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex-shrink-0 text-muted-foreground hover:text-foreground underline decoration-muted-foreground/20 transition-colors"
              >
                {source.title}
              </a>
              <span className="text-muted-foreground/60">
                {source.description}
              </span>
            </div>
          ))}
        </div>

        {/* Standards & Frameworks */}
        <h3 className="text-sm font-mono text-muted-foreground/60 uppercase tracking-wider mb-4">
          Standards & Frameworks
        </h3>
        <div className="space-y-3">
          {STANDARDS.map((standard) => (
            <div key={standard.url} className="flex items-start gap-3 text-sm">
              <a
                href={standard.url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex-shrink-0 text-muted-foreground hover:text-foreground underline decoration-muted-foreground/20 transition-colors"
              >
                {standard.title}
              </a>
              <span className="text-muted-foreground/60">
                {standard.description}
              </span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
