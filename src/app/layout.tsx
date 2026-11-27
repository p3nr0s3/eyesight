import type { Metadata, Viewport } from "next";
import {
  Inter,
  JetBrains_Mono,
  Space_Grotesk,
  IBM_Plex_Sans,
} from "next/font/google";
import "./globals.css";
import { AppShell } from "@/components/AppShell";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

const jetbrains = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains",
  display: "swap",
});

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-space",
  display: "swap",
});

const ibmPlex = IBM_Plex_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-ibm",
  display: "swap",
});

export const metadata: Metadata = {
  title: "EYESIGHT — THREAT INTELLIGENCE HUB",
  description:
    "Unified Threat Intelligence IOC enrichment console across VirusTotal, AbuseIPDB, abuse.ch, OTX, Shodan, GreyNoise, CVE Lookup, and Cybersecurity News.",
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      data-theme="obsidian"
      className={`dark ${inter.variable} ${jetbrains.variable} ${spaceGrotesk.variable} ${ibmPlex.variable}`}
      suppressHydrationWarning
    >
      <body className="min-h-screen w-full antialiased selection:bg-cyan-500/30 selection:text-cyan-200">
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
