import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import { Header } from "@/components/Header";
import "./globals.css";

const plexSans = IBM_Plex_Sans({
  variable: "--font-sans-family",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

const plexMono = IBM_Plex_Mono({
  variable: "--font-mono-family",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
});

export const metadata: Metadata = {
  title: "PolicyForge Portal",
  description: "Self-hosted policy-as-code scan dashboard",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${plexSans.variable} ${plexMono.variable}`}>
      <body>
        <Header />
        <main className="shell">{children}</main>
        <footer className="footer">
          Self-hosted PolicyForge enterprise portal. No compliance
          framework mapping yet — see <code>enterprise/DESIGN.md</code>.
        </footer>
      </body>
    </html>
  );
}
