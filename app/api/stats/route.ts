import { NextResponse } from "next/server";
import { getAggregateStats } from "@/lib/haveibeenclawned";

export async function GET() {
  const stats = await getAggregateStats();
  return NextResponse.json(stats, {
    headers: {
      "Cache-Control": "public, s-maxage=60, stale-while-revalidate=300",
    },
  });
}
