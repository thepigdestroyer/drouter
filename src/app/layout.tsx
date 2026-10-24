import type { Metadata, Viewport } from "next";
import { InkField } from "@/components/ink/ink-field";
import "./globals.css";

const SITE_URL = "https://drouter-demo.vercel.app";
const DEFAULT_TITLE = "deRoute | Private AI Routing";
const DEFAULT_DESCRIPTION =
  "Ask frontier AI models without anyone, including us, reading what you write. Your device checks the seal on a locked computer and hides your personal details before anything leaves your screen.";

export const viewport: Viewport = {
  themeColor: "#f3f1ec",
  colorScheme: "light",
};

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: DEFAULT_TITLE,
    template: "%s | deRoute",
  },
  description: DEFAULT_DESCRIPTION,
  applicationName: "deRoute",
  alternates: {
    canonical: SITE_URL,
  },
  openGraph: {
    title: DEFAULT_TITLE,
    description: DEFAULT_DESCRIPTION,
    url: SITE_URL,
    siteName: "deRoute",
    locale: "en_US",
    type: "website",
    images: [
      {
        url: "/opengraph-image",
        width: 1200,
        height: 630,
        alt: "deRoute private AI routing diagram",
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
      <body className="relative min-h-full flex flex-col bg-paper text-ink">
        <InkField />
        <div className="relative z-10 flex min-h-full flex-1 flex-col">
          {children}
        </div>
      </body>
    </html>
  );
}
