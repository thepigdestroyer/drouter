import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "deRoute | Private AI Routing",
    short_name: "deRoute",
    description:
      "Ask frontier AI models without anyone, including us, reading what you write. Your device checks the seal on a locked computer and hides your personal details before anything leaves your screen.",
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
