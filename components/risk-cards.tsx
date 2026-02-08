export function RiskCards() {
  return (
    <section className="py-24 px-4">
      <div className="max-w-4xl mx-auto">
        <h2 className="text-3xl md:text-4xl font-bold text-foreground text-center mb-4">
          What&apos;s actually at risk
        </h2>
        <p className="text-lg text-muted-foreground text-center mb-12 max-w-2xl mx-auto">
          Most OpenClaw agents run with zero security. Here&apos;s what that means.
        </p>

        <p className="text-3xl md:text-5xl font-black text-foreground leading-tight">
          Account takeover <span className="text-red-500/30">/</span> Identity theft <span className="text-red-500/30">/</span> Full system compromise
        </p>
        <div className="h-1 w-24 bg-gradient-to-r from-red-500/50 to-orange-500/30 rounded-full mt-6 mb-8" />
        <div className="grid gap-8 md:grid-cols-3">
          <p className="text-sm text-muted-foreground leading-relaxed">Your agent has your email. Your email has your MFA codes, password resets, and account recovery. One compromised agent = every account that uses email verification.</p>
          <p className="text-sm text-muted-foreground leading-relaxed">Unverified skills run with full agent permissions. They can read your documents, credentials, and personal data &mdash; then exfiltrate it silently. Everything an attacker needs to become you.</p>
          <p className="text-sm text-muted-foreground leading-relaxed">No sandbox means the agent sees your filesystem, network, and every credential on disk. SSH keys, cloud tokens, browser sessions &mdash; all reachable. One breach, total access.</p>
        </div>
      </div>
    </section>
  );
}
