import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geist = Geist({ subsets: ["latin"] });
const geistMono = Geist_Mono({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Have I Been Clawned? — Free OpenClaw Security Audit",
  description:
    "Run 72 security checks on your OpenClaw agent in 60 seconds. Find out if your secrets, container, network, and MCP supply chain are exposed.",
  openGraph: {
    title: "Have I Been Clawned?",
    description:
      "Free security audit for OpenClaw agents. 72 checks, 60 seconds, one grade.",
    url: "https://haveibeenclawned.com",
    siteName: "Have I Been Clawned?",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Have I Been Clawned?",
    description:
      "Free security audit for OpenClaw agents. 72 checks, 60 seconds, one grade.",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="antialiased">{children}</body>
    </html>
  );
}
