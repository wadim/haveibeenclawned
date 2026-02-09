"use client";

import { useState } from "react";

const AGENT_PROMPT = "Run the open-source security audit from github.com/wadim/haveibeenclawned (MIT license). Download public/audit.sh from the repo, review it, and run it.";
const SCRIPT_CMD = "curl -sSL https://raw.githubusercontent.com/wadim/haveibeenclawned/main/public/audit.sh -o /tmp/hibc-audit.sh && cat /tmp/hibc-audit.sh && bash /tmp/hibc-audit.sh";

export function InstallSteps() {
  const [copiedAgent, setCopiedAgent] = useState(false);
  const [copiedScript, setCopiedScript] = useState(false);

  const handleCopyAgent = async () => {
    await navigator.clipboard.writeText(AGENT_PROMPT);
    setCopiedAgent(true);
    setTimeout(() => setCopiedAgent(false), 2000);
  };

  const handleCopyScript = async () => {
    await navigator.clipboard.writeText(SCRIPT_CMD);
    setCopiedScript(true);
    setTimeout(() => setCopiedScript(false), 2000);
  };

  return (
    <section className="py-24 px-4">
      <div className="max-w-3xl mx-auto">
        <h2 className="text-3xl md:text-4xl font-bold text-foreground text-center mb-4">
          Audit your agent in 60 seconds
        </h2>
        <p className="text-lg text-muted-foreground text-center mb-12">
          Two ways to run. Pick whichever fits.
        </p>

        <div className="grid gap-4 md:grid-cols-2">
          {/* Option 1: Tell your agent */}
          <div className="rounded-2xl border border-border/50 bg-card/30 p-6 flex flex-col">
            <div className="text-xs font-mono text-muted-foreground/50 mb-3">
              Option 1 — Tell your agent
            </div>
            <div
              onClick={handleCopyAgent}
              className="group cursor-pointer flex-1 rounded-xl bg-background/50 hover:bg-background/80 transition-colors p-4"
            >
              <p className="font-mono text-sm text-foreground leading-relaxed">
                &ldquo;{AGENT_PROMPT}&rdquo;
              </p>
              <p className="text-xs text-muted-foreground mt-3">
                {copiedAgent ? (
                  <span className="text-green-400">Copied</span>
                ) : (
                  "Click to copy"
                )}
              </p>
            </div>
            <p className="text-xs text-muted-foreground/60 mt-3">
              Agent downloads the audit script, reviews it, and runs it.
            </p>
          </div>

          {/* Option 2: Run it yourself */}
          <div className="rounded-2xl border border-border/50 bg-card/30 p-6 flex flex-col">
            <div className="text-xs font-mono text-muted-foreground/50 mb-3">
              Option 2 — Run it yourself
            </div>
            <div
              onClick={handleCopyScript}
              className="group cursor-pointer flex-1 rounded-xl bg-background/50 hover:bg-background/80 transition-colors p-4"
            >
              <p className="font-mono text-xs text-foreground leading-relaxed break-all">
                curl -sSL https://haveibeenclawned.com/audit.sh -o /tmp/hibc-audit.sh<br />
                cat /tmp/hibc-audit.sh<br />
                bash /tmp/hibc-audit.sh
              </p>
              <p className="text-xs text-muted-foreground mt-3">
                {copiedScript ? (
                  <span className="text-green-400">Copied</span>
                ) : (
                  "Click to copy"
                )}
              </p>
            </div>
            <p className="text-xs text-muted-foreground/60 mt-3">
              Download, review, and run. No dependencies beyond bash.
            </p>
          </div>
        </div>

        <p className="text-sm text-muted-foreground text-center mt-8">
          72 checks run locally. Nothing leaves your machine.
          <br />
          <a
            href="https://github.com/wadim/haveibeenclawned"
            target="_blank"
            rel="noopener noreferrer"
            className="text-muted-foreground/60 hover:text-muted-foreground underline decoration-muted-foreground/20"
          >
            Read the source code
          </a>
        </p>
      </div>
    </section>
  );
}
