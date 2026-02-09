import { NextResponse } from "next/server";
import { createHash } from "crypto";
import { readFileSync } from "fs";
import { join } from "path";

export async function GET() {
  const scriptPath = join(process.cwd(), "public", "audit.sh");
  const content = readFileSync(scriptPath);
  const sha256 = createHash("sha256").update(content).digest("hex");

  return NextResponse.json(
    {
      file: "audit.sh",
      sha256,
      source: "https://github.com/wadim/haveibeenclawned/blob/main/audit.sh",
      license: "MIT",
      repository: "https://github.com/wadim/haveibeenclawned",
    },
    {
      headers: {
        "Cache-Control": "public, s-maxage=300, stale-while-revalidate=600",
      },
    },
  );
}
