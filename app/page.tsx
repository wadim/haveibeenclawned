import { StatsBanner } from "@/components/stats-banner";
import { RiskCards } from "@/components/risk-cards";
import { InstallSteps } from "@/components/install-steps";
import { AgentInstructions } from "@/components/agent-instructions";
import { References } from "@/components/references";

export default function HaveIBeenClawnedPage() {
  return (
    <main className="min-h-screen bg-background">
      {/* Nav */}
      <header className="border-b border-border/50">
        <div className="max-w-4xl mx-auto px-4 py-4 flex items-center justify-between">
          <span className="flex items-center gap-2 text-sm font-medium text-foreground">
            <img src="/logo.png" alt="" width={24} height={24} className="rounded-sm" />
            Have I Been Clawned?
          </span>
          <a
            href="https://github.com/wadim/haveibeenclawned"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            GitHub
          </a>
        </div>
      </header>

      {/* Hero */}
      <section className="py-24 md:py-32 px-4">
        <div className="max-w-4xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-border/50 bg-card/30 text-sm text-muted-foreground mb-8">
            <span className="w-2 h-2 rounded-full bg-red-500/80 animate-pulse" />
            Free security audit for OpenClaw agents
          </div>

          <h1 className="text-5xl md:text-7xl font-bold text-foreground tracking-tight mb-6 flex items-center justify-center gap-5">
            <img src="/logo.png" alt="" width={160} height={160} className="shrink-0" />
            <span>
              Have I Been
              <br />
              <span className="bg-gradient-to-r from-red-500/90 to-orange-500/90 bg-clip-text text-transparent">
                Clawned
              </span>
              ?
            </span>
          </h1>

          <p className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto mb-4">
            72 security checks. 60 seconds. One grade.
            <br />
            Find out if your agent is leaking secrets, running unverified
            skills, or exposing your identity.
          </p>

          <StatsBanner />

          <div className="mt-10">
            <a
              href="#audit"
              className="inline-flex items-center gap-2 px-8 py-4 rounded-xl bg-foreground text-background font-semibold text-lg hover:bg-foreground/90 transition-colors"
            >
              Audit your agent
            </a>
          </div>
        </div>
      </section>

      {/* Risk Cards */}
      <RiskCards />

      {/* What we cover */}
      <section className="py-24 px-4 border-t border-border/50">
        <div className="max-w-3xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-bold text-foreground text-center mb-4">
            Beyond the config file
          </h2>
          <p className="text-lg text-muted-foreground text-center mb-12 max-w-2xl mx-auto">
            OpenClaw&apos;s built-in <code className="text-sm px-2 py-1 rounded bg-card/50 border border-border/50 font-mono">security audit</code> is
            solid for checking your gateway config. This tool goes further &mdash; the host, the container,
            the network, the secrets on disk, and the MCP supply chain around your agent.
          </p>

          <div className="rounded-2xl border border-border/50 bg-card/30 p-8">
            <h3 className="text-lg font-bold text-foreground mb-4">72 checks across 9 categories</h3>
            <div className="grid gap-x-8 gap-y-3 sm:grid-cols-2 text-sm text-muted-foreground">
              <div className="flex items-start gap-2"><span className="text-green-500/70 mt-0.5">&#10003;</span> Container isolation: privileged mode, root, seccomp, namespaces</div>
              <div className="flex items-start gap-2"><span className="text-green-500/70 mt-0.5">&#10003;</span> Secrets in transcripts, git history, env files &amp; shell history</div>
              <div className="flex items-start gap-2"><span className="text-green-500/70 mt-0.5">&#10003;</span> MCP server CVEs, tool shadowing &amp; description poisoning</div>
              <div className="flex items-start gap-2"><span className="text-green-500/70 mt-0.5">&#10003;</span> Cloud metadata SSRF, egress filtering &amp; firewall rules</div>
              <div className="flex items-start gap-2"><span className="text-green-500/70 mt-0.5">&#10003;</span> Skill supply chain: typosquatting, npm scripts, threat intel</div>
              <div className="flex items-start gap-2"><span className="text-green-500/70 mt-0.5">&#10003;</span> Browser profiles, git credentials, DB credentials, wallets</div>
              <div className="flex items-start gap-2"><span className="text-green-500/70 mt-0.5">&#10003;</span> Memory poisoning, dormant payloads &amp; rules file injection</div>
              <div className="flex items-start gap-2"><span className="text-green-500/70 mt-0.5">&#10003;</span> Config hardening: sandbox, permissions, auto-approve, log redaction</div>
              <div className="flex items-start gap-2"><span className="text-green-500/70 mt-0.5">&#10003;</span> Agent identity, code integrity &amp; persistence paths</div>
            </div>
          </div>

          <p className="text-sm text-muted-foreground/60 text-center mt-8">
            Works whether or not you have CLI access to run the built-in audit.
            <br />
            If you do &mdash; run both. They&apos;re complementary.
          </p>
        </div>
      </section>

      {/* Install Steps */}
      <InstallSteps />

      {/* Agent-readable instructions (also useful for curious humans) */}
      <AgentInstructions />

      {/* References */}
      <References />

      {/* Contribute CTA */}
      <section className="py-24 px-4">
        <div className="max-w-3xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-bold text-foreground text-center mb-4">
            Run it. Break it. Improve it.
          </h2>
          <p className="text-lg text-muted-foreground text-center mb-12 max-w-2xl mx-auto">
            Security is a moving target. We need the community to keep this tool sharp.
          </p>

          <div className="grid gap-4 md:grid-cols-3 mb-12">
            <div className="rounded-2xl border border-border/50 bg-card/30 p-6">
              <p className="text-sm font-semibold text-foreground mb-2">Test it</p>
              <p className="text-sm text-muted-foreground leading-relaxed">
                Run the audit on your agent. Report false positives. Tell us what we miss.
                Your environment is different from ours &mdash; that&apos;s the point.
              </p>
            </div>
            <div className="rounded-2xl border border-border/50 bg-card/30 p-6">
              <p className="text-sm font-semibold text-foreground mb-2">Add checks</p>
              <p className="text-sm text-muted-foreground leading-relaxed">
                Found an attack vector we don&apos;t cover? New CVE? New misconfiguration?
                Add a check with a verified detection and a concrete fix command.
              </p>
            </div>
            <div className="rounded-2xl border border-border/50 bg-card/30 p-6">
              <p className="text-sm font-semibold text-foreground mb-2">Share threat intel</p>
              <p className="text-sm text-muted-foreground leading-relaxed">
                New C2 IPs, malicious domains, IOC patterns, known-bad publishers.
                The threat intel arrays in the script are community-maintained.
              </p>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <a
              href="https://github.com/wadim/haveibeenclawned"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-8 py-4 rounded-xl bg-foreground text-background font-semibold text-lg hover:bg-foreground/90 transition-colors"
            >
              Star on GitHub
            </a>
            <a
              href="https://github.com/wadim/haveibeenclawned/blob/main/CONTRIBUTING.md"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-8 py-4 rounded-xl border border-border/50 text-foreground font-semibold text-lg hover:bg-card/50 transition-colors"
            >
              Contributing guide
            </a>
          </div>
          <p className="text-sm text-muted-foreground text-center mt-4">
            Open source. Free forever.
          </p>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border/50 py-8 px-4">
        <div className="max-w-4xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-muted-foreground">
          <p className="flex items-center gap-2">
            <a href="https://linkedin.com/in/wadimgrasza" target="_blank" rel="noopener noreferrer" className="hover:text-foreground transition-colors">Wadim Grasza</a>
            <span className="text-muted-foreground/30">&middot;</span>
            <a href="https://github.com/wadim/haveibeenclawned" target="_blank" rel="noopener noreferrer" className="hover:text-foreground transition-colors">GitHub</a>
            <span className="text-muted-foreground/30">&middot;</span>
            <a href="https://github.com/wadim/haveibeenclawned/security/policy" target="_blank" rel="noopener noreferrer" className="hover:text-foreground transition-colors">Security Policy</a>
          </p>
          <p className="text-muted-foreground/60">
            Not affiliated with haveibeenpwned.com
          </p>
        </div>
      </footer>
    </main>
  );
}
