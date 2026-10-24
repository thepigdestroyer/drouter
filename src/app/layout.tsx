import type { Metadata, Viewport } from "next";
import "./globals.css";

const SITE_URL = "https://drouter-demo.vercel.app";
const DEFAULT_TITLE = "dRouter · Confidential AI Router";
const DEFAULT_DESCRIPTION =
  "Ask frontier AI models without anyone, including us, reading your prompt. Browser-verified AMD SEV-SNP and Intel TDX hardware attestation with HPKE encryption.";

export const viewport: Viewport = {
  themeColor: "#f3f1ec",
  colorScheme: "light",
};

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: DEFAULT_TITLE,
    template: "%s · dRouter",
  },
  description: DEFAULT_DESCRIPTION,
  applicationName: "dRouter",
  alternates: {
    canonical: SITE_URL,
  },
  openGraph: {
    title: DEFAULT_TITLE,
    description: DEFAULT_DESCRIPTION,
    url: SITE_URL,
    siteName: "dRouter",
    locale: "en_US",
    type: "website",
    images: [
      {
        url: "/opengraph-image",
        width: 1200,
        height: 630,
        alt: "dRouter confidential AI router dataflow diagram",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: DEFAULT_TITLE,
    description: DEFAULT_DESCRIPTION,
    images: ["/twitter-image"],
  },
  icons: {
    icon: [
      { url: "/icon.svg", type: "image/svg+xml", sizes: "any" },
      { url: "/favicon.ico", sizes: "any" },
    ],
  },
  manifest: "/manifest.webmanifest",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col bg-paper text-ink">{children}</body>
    </html>
  );
}
