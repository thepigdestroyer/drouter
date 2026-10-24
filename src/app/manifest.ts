import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "dRouter · Confidential AI Router",
    short_name: "dRouter",
    description:
      "Ask frontier AI models without anyone, including us, reading your prompt. Browser-verified AMD SEV-SNP and Intel TDX hardware attestation with HPKE encryption.",
    start_url: "/",
    display: "standalone",
    background_color: "#f3f1ec",
    theme_color: "#f3f1ec",
    icons: [
      {
        src: "/icon.svg",
        sizes: "any",
        type: "image/svg+xml",
        purpose: "any",
      },
      {
        src: "/brand/drouter-mark.svg",
        sizes: "any",
        type: "image/svg+xml",
      },
      {
        src: "/favicon.ico",
        sizes: "any",
        type: "image/x-icon",
      },
    ],
  };
}
