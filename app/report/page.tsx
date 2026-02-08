import type { Metadata } from "next";
import Link from "next/link";
import { decodeReport } from "@/lib/haveibeenclawned";
import { ReportCard } from "@/components/report-card";

const GRADE_LABELS: Record<string, string> = {
  A: "Hardened",
  B: "Good",
  C: "Needs Work",
  D: "Exposed",
  F: "Critical",
};

type Props = {
  searchParams: Promise<{ d?: string }>;
};

export async function generateMetadata({ searchParams }: Props): Promise<Metadata> {
  const { d } = await searchParams;
  const report = d ? decodeReport(d) : null;

  if (!report) {
    return {
      title: "Security Report — Have I Been Clawned?",
    };
  }

  const label = GRADE_LABELS[report.g] || "Unknown";
  const failCount = report.r.filter((v) => v === 0).length;

  return {
    title: `${report.s}/100 — Grade ${report.g}: ${label} — Have I Been Clawned?`,
    description: `This OpenClaw agent scored ${report.s}/100 (Grade ${report.g}) with ${failCount} failing check${failCount !== 1 ? "s" : ""}. Run your own free security audit.`,
    openGraph: {
      title: `${report.s}/100 — Grade ${report.g} — Have I Been Clawned?`,
      description: `${failCount} security issue${failCount !== 1 ? "s" : ""} found. ${label}. Run your own free audit at haveibeenclawned.com`,
      url: `https://haveibeenclawned.com/report`,
      siteName: "Have I Been Clawned?",
      type: "website",
    },
    twitter: {
      card: "summary",
      title: `${report.s}/100 — Grade ${report.g} — Have I Been Clawned?`,
      description: `${failCount} security issue${failCount !== 1 ? "s" : ""} found. Run your own free audit at haveibeenclawned.com`,
    },
  };
}

export default async function ReportPage({ searchParams }: Props) {
  const { d } = await searchParams;
  const report = d ? decodeReport(d) : null;

  if (!report) {
    return (
      <main className="min-h-screen bg-background flex items-center justify-center px-4">
        <div className="text-center">
          <h1 className="text-3xl font-bold text-foreground mb-4">
            Invalid report link
          </h1>
          <p className="text-muted-foreground mb-8">
            This link doesn&apos;t contain a valid scan report.
          </p>
          <Link
            href="/"
            className="text-foreground underline hover:no-underline"
          >
            Run your own audit &rarr;
          </Link>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-background">
      {/* Nav */}
      <header className="border-b border-border/50">
        <div className="max-w-4xl mx-auto px-4 py-4 flex items-center justify-between">
          <Link
            href="/"
            className="text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            &larr; Have I Been Clawned?
          </Link>
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

      <section className="py-16 md:py-24 px-4">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-3xl md:text-4xl font-bold text-foreground text-center mb-2">
            Security Report
          </h1>
          <p className="text-muted-foreground text-center mb-12">
            OpenClaw agent security audit — 72 checks, OWASP-mapped
          </p>

          <ReportCard report={report} />
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border/50 py-8 px-4">
        <div className="max-w-4xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-muted-foreground">
          <Link
            href="/"
            className="hover:text-foreground transition-colors"
          >
            Run your own audit
          </Link>
          <p className="text-muted-foreground/60">
            Open source. Free forever.
          </p>
        </div>
      </footer>
    </main>
  );
}
