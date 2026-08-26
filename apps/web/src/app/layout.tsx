import type { Metadata } from "next";
import { JetBrains_Mono } from "next/font/google";
import localFont from "next/font/local";
import "./globals.css";

// Self-hosted full-feature InterVariable. The Google Fonts build of Inter
// ships without the character-variant / stylistic-set tables, so cv05 (tailed
// l), cv08 (serifed I) and slashed-zero never rendered — verified in-browser
// (feature on/off were identical). The official InterVariable.woff2 includes
// them; globals.css enables them via font-feature-settings. variable:
// "--font-inter" preserves the existing theme wiring unchanged.
const inter = localFont({
  src: "./fonts/InterVariable.woff2",
  variable: "--font-inter",
  weight: "100 900",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "Maljan - Multi-Agent Malware Analysis",
  description:
    "Professional multi-agent malware analysis platform with AI-powered threat intelligence.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <body>{children}</body>
    </html>
  );
}
