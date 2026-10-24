import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "dRouter · Verifiable Confidential AI Router",
  description:
    "End-to-end encrypted, hardware-attested AI inference router with two-hop AMD SEV-SNP + Confidential GPU verification, blind-signed credits, and on-chain accountability on Circle Arc.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col bg-[#050506] text-zinc-100">{children}</body>
    </html>
  );
}
