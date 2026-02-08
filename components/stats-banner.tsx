"use client";

import { useEffect, useState } from "react";
import type { AggregateStats } from "@/lib/haveibeenclawned";

export function StatsBanner() {
  const [stats, setStats] = useState<AggregateStats | null>(null);

  useEffect(() => {
    fetch("/api/stats")
      .then((r) => r.json())
      .then(setStats)
      .catch(() => {});
  }, []);

  const total = stats?.totalScans ?? 0;
  const avgScore = stats?.avgScore ?? 0;
  const criticalPct = stats?.criticalPct ?? 0;

  if (total === 0) {
    return (
      <div className="flex flex-wrap justify-center gap-8 mt-8">
        <StatItem value="Be the first" label="to scan your agent" />
      </div>
    );
  }

  return (
    <div className="flex flex-wrap justify-center gap-8 md:gap-12 mt-8">
      <StatItem value={total.toLocaleString()} label="agents scanned" />
      <StatItem value={`${avgScore}/100`} label="avg hardening score" />
      <StatItem value={`${criticalPct}%`} label="have critical issues" />
    </div>
  );
}

function StatItem({ value, label }: { value: string; label: string }) {
  return (
    <div className="text-center">
      <p className="text-2xl md:text-3xl font-bold text-foreground font-mono">
        {value}
      </p>
      <p className="text-sm text-muted-foreground mt-1">{label}</p>
    </div>
  );
}
