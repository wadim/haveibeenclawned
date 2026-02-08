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

        <div className="grid gap-4 md:grid-cols-3">
          {/* Card 1: Personal email */}
          <div className="rounded-2xl border border-border/50 bg-card/30 p-8">
            <div className="mb-6">
              <svg viewBox="0 0 200 120" fill="none" className="w-full" aria-hidden="true">
                {/* Email envelope */}
                <rect x="40" y="25" width="120" height="70" rx="8" stroke="rgb(239 68 68 / 0.4)" strokeWidth="1.5" fill="rgb(239 68 68 / 0.04)" />
                <path d="M40 33l60 35 60-35" stroke="rgb(239 68 68 / 0.4)" strokeWidth="1.5" fill="none" />
                {/* @ symbol */}
                <circle cx="100" cy="62" r="12" stroke="rgb(255 255 255 / 0.15)" strokeWidth="1" fill="none" />
                <circle cx="103" cy="62" r="5" stroke="rgb(255 255 255 / 0.2)" strokeWidth="1" fill="none" />
                <path d="M108 67c0 0-2 3-8 3-7 0-12-5-12-12s5-12 12-12 12 5 12 12v2" stroke="rgb(255 255 255 / 0.2)" strokeWidth="1" fill="none" />
                {/* Warning badge */}
                <circle cx="150" cy="30" r="10" fill="rgb(239 68 68 / 0.15)" stroke="rgb(239 68 68 / 0.5)" strokeWidth="1" />
                <text x="150" y="34" fontSize="12" textAnchor="middle" fill="rgb(239 68 68 / 0.7)" fontFamily="ui-monospace, monospace">!</text>
              </svg>
            </div>
            <h3 className="text-lg font-bold text-foreground mb-2">
              Your email is the agent&apos;s email
            </h3>
            <p className="text-sm text-muted-foreground leading-relaxed">
              Your agent sends from your personal address. If it gets compromised, attackers send as you — to your contacts, your bank, your employer.
            </p>
          </div>

          {/* Card 2: Malicious skills */}
          <div className="rounded-2xl border border-border/50 bg-card/30 p-8">
            <div className="mb-6">
              <svg viewBox="0 0 200 120" fill="none" className="w-full" aria-hidden="true">
                {/* Grid of skill blocks */}
                {[0, 1, 2, 3, 4, 5].map((i) => {
                  const x = 30 + (i % 3) * 50;
                  const y = 15 + Math.floor(i / 3) * 45;
                  const isMalicious = i === 2 || i === 4;
                  return (
                    <g key={i}>
                      <rect
                        x={x}
                        y={y}
                        width="40"
                        height="35"
                        rx="6"
                        stroke={isMalicious ? "rgb(239 68 68 / 0.4)" : "rgb(255 255 255 / 0.1)"}
                        strokeWidth="1"
                        fill={isMalicious ? "rgb(239 68 68 / 0.06)" : "rgb(255 255 255 / 0.02)"}
                      />
                      {isMalicious && (
                        <>
                          <line x1={x + 12} y1={y + 10} x2={x + 28} y2={y + 26} stroke="rgb(239 68 68 / 0.5)" strokeWidth="1.5" strokeLinecap="round" />
                          <line x1={x + 28} y1={y + 10} x2={x + 12} y2={y + 26} stroke="rgb(239 68 68 / 0.5)" strokeWidth="1.5" strokeLinecap="round" />
                        </>
                      )}
                      {!isMalicious && (
                        <rect x={x + 10} y={y + 14} width="20" height="7" rx="2" fill="rgb(255 255 255 / 0.06)" />
                      )}
                    </g>
                  );
                })}
                {/* No verified badge anywhere */}
                <text x="100" y="110" fontSize="7" textAnchor="middle" fill="rgb(239 68 68 / 0.4)" fontFamily="ui-monospace, monospace">no verification</text>
              </svg>
            </div>
            <h3 className="text-lg font-bold text-foreground mb-2">
              Unverified skills. Zero warnings.
            </h3>
            <p className="text-sm text-muted-foreground leading-relaxed">
              ClawHub skills run with full agent permissions. A malicious skill can exfiltrate data, inject prompts, or hijack your agent — silently.
            </p>
          </div>

          {/* Card 3: No sandbox */}
          <div className="rounded-2xl border border-border/50 bg-card/30 p-8">
            <div className="mb-6">
              <svg viewBox="0 0 200 120" fill="none" className="w-full" aria-hidden="true">
                {/* Broken container outline */}
                <rect x="40" y="15" width="120" height="90" rx="10" stroke="rgb(255 255 255 / 0.08)" strokeWidth="1.5" strokeDasharray="6 4" fill="none" />
                {/* Agent in center — exposed */}
                <circle cx="100" cy="60" r="16" stroke="rgb(255 255 255 / 0.15)" strokeWidth="1" fill="rgb(255 255 255 / 0.03)" />
                <circle cx="100" cy="60" r="6" fill="rgb(255 255 255 / 0.1)" />
                {/* Arrows pointing outward — data escaping */}
                <path d="M120 45l20-15" stroke="rgb(239 68 68 / 0.4)" strokeWidth="1.5" strokeLinecap="round" />
                <path d="M136 27l4 3-1-5" stroke="rgb(239 68 68 / 0.4)" strokeWidth="1" fill="rgb(239 68 68 / 0.4)" />
                <path d="M120 75l20 15" stroke="rgb(239 68 68 / 0.4)" strokeWidth="1.5" strokeLinecap="round" />
                <path d="M136 93l4-3-1 5" stroke="rgb(239 68 68 / 0.4)" strokeWidth="1" fill="rgb(239 68 68 / 0.4)" />
                <path d="M80 45l-20-15" stroke="rgb(239 68 68 / 0.4)" strokeWidth="1.5" strokeLinecap="round" />
                <path d="M64 27l-4 3 1-5" stroke="rgb(239 68 68 / 0.4)" strokeWidth="1" fill="rgb(239 68 68 / 0.4)" />
                {/* Label */}
                <text x="100" y="110" fontSize="7" textAnchor="middle" fill="rgb(239 68 68 / 0.4)" fontFamily="ui-monospace, monospace">no containment</text>
              </svg>
            </div>
            <h3 className="text-lg font-bold text-foreground mb-2">
              No sandbox? No safety net.
            </h3>
            <p className="text-sm text-muted-foreground leading-relaxed">
              Without container isolation, a compromised agent has access to your filesystem, network, and credentials. Everything on that machine is fair game.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
