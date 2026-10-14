import type { Metadata, Viewport } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { AuroraBackdrop } from "@/components/AuroraBackdrop";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

const mono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "VeriTrace — AI Provenance Forensics & Document Hygiene",
  description:
    "Zero-trust, $0, local-first document forensics: binary & C2PA container analysis, Unicode steganography / prompt-injection detection, SynthID & Kirchenbauer entropy visualization, and entity-locked sanitization.",
  keywords: [
    "AI provenance",
    "SynthID",
    "watermark detection",
    "prompt injection",
    "Unicode steganography",
    "C2PA",
    "document forensics",
  ],
  authors: [{ name: "Ameer Sohail Shaik" }],
  robots: { index: true, follow: true },
  openGraph: {
    title: "VeriTrace — AI Provenance Forensics",
    description:
      "Four-layer document forensics & zero-trust sanitization. Runs at $0, local-first.",
    type: "website",
  },
};

export const viewport: Viewport = {
  themeColor: "#06080D",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${inter.variable} ${mono.variable}`}>
      <body>
        <AuroraBackdrop />
        {children}
      </body>
    </html>
  );
}
