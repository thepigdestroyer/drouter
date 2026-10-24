import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "dRouter · Confidential AI Router",
  description:
    "Ask frontier AI models without anyone, including us, reading your prompt. Browser-verified AMD SEV-SNP and Intel TDX hardware attestation with HPKE encryption.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col bg-paper text-ink">{children}</body>
    </html>
  );
}
