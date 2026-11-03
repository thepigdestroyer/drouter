import type { Metadata } from "next";

export const SITE_URL = "https://drouter-demo.vercel.app";
export const SITE_NAME = "deRoute";
export const INDEXNOW_KEY = "b3e3066c7789b0706e31f432ae6f20bf";
export const AWARD = "Winner, Agents That Ship track, Encode London 2026";

export const PERSON_ID = "https://mrinal.is-a.dev/#person";
export const PERSON_URL = "https://mrinal.is-a.dev/";

export const PERSON_REF = {
  "@type": "Person",
  "@id": PERSON_ID,
  name: "Mrinal Joshi",
  url: PERSON_URL,
} as const;

export const MORE_BY_MRINAL: ReadonlyArray<{ label: string; href: string }> = [
  { label: "Portfolio", href: "https://mrinal.is-a.dev/" },
  { label: "AI Studio", href: "https://m-joshi.ai.studio/" },
  { label: "Positive Control", href: "https://m-lab.is-an.ai/" },
  { label: "A day at the bench", href: "https://mj-forge.is-an.ai/" },
  { label: "Hearth", href: "https://hearth.is-an.ai/" },
  { label: "FLAIR-AD", href: "https://flair-ad.netlify.app/" },
];

export interface SeoPage {
  path: string;
  title: string;
  description: string;
  breadcrumb: string;
  lastModified: string;
  changeFrequency: "hourly" | "weekly" | "monthly";
  priority: number;
}

export const SEO_PAGES: ReadonlyArray<SeoPage> = [
  {
    path: "/",
    title: "Private AI Routing: Confidential, Verifiable | deRoute",
    description:
      "deRoute is private AI routing you can check. Your browser verifies the sealed hardware first and hides your personal details, so nobody reads your prompt.",
    breadcrumb: "Home",
    lastModified: "2026-11-03",
    changeFrequency: "weekly",
    priority: 1.0,
  },
  {
    path: "/explain",
    title: "How Private AI Routing Works, Step by Step | deRoute",
    description:
      "A short story in four scenes: how deRoute checks the seal on a distant computer, hides your personal details, locks your message and dissolves the key after.",
    breadcrumb: "How it works",
    lastModified: "2026-11-03",
    changeFrequency: "weekly",
    priority: 0.9,
  },
  {
    path: "/about",
    title: "Confidential AI and Its Honest Limits | deRoute",
    description:
      "What deRoute protects today and its honest limits: personal details hidden on your device, equal-sized messages and one sealed computer that opens your prompt.",
    breadcrumb: "About",
    lastModified: "2026-11-03",
    changeFrequency: "monthly",
    priority: 0.85,
  },
  {
    path: "/partners",
    title: "Confidential AI Backend Partners | deRoute",
    description:
      "How Google Gemini and MongoDB Atlas work inside deRoute without receiving your plain messages, personal details or IP address, and what each partner can see.",
    breadcrumb: "Backend partners",
    lastModified: "2026-11-03",
    changeFrequency: "monthly",
    priority: 0.85,
  },
  {
    path: "/app",
    title: "Private ChatGPT Alternative with Attestation | deRoute",
    description:
      "Chat with frontier AI models privately. deRoute checks the hardware seal in your browser, hides personal details on your device and sends only a locked message.",
    breadcrumb: "Private chat",
    lastModified: "2026-11-03",
    changeFrequency: "weekly",
    priority: 0.85,
  },
  {
    path: "/argon",
    title: "Private AI Agent for Multi-Step Tasks | deRoute",
    description:
      "A private AI agent that plans multi-step tasks over scrubbed metadata with Google Gemini 4 Argon, while your words stay locked for the sealed computer alone.",
    breadcrumb: "Private AI agent",
    lastModified: "2026-11-03",
    changeFrequency: "weekly",
    priority: 0.8,
  },
  {
    path: "/audit",
    title: "Verifiable AI Privacy: Check deRoute Yourself | deRoute",
    description:
      "Do not take our word for it. Check the lock on the sealed computer and the public receipt book behind every deRoute chat, and verify the claims yourself.",
    breadcrumb: "Proof",
    lastModified: "2026-11-03",
    changeFrequency: "weekly",
    priority: 0.8,
  },
  {
    path: "/network",
    title: "Confidential AI Network and Public Receipt Book | deRoute",
    description:
      "See the sealed computers that answer deRoute chats and the public receipt book recording every hardware seal check, so AI prompt privacy can be verified.",
    breadcrumb: "Network",
    lastModified: "2026-11-03",
    changeFrequency: "hourly",
    priority: 0.75,
  },
  {
    path: "/login",
    title: "Sign In Without Email or Password | deRoute",
    description:
      "Sign in to deRoute with your fingerprint, face, device or six secret words. No email and no password, so we never learn who you are. Nothing else to remember.",
    breadcrumb: "Sign in",
    lastModified: "2026-11-03",
    changeFrequency: "monthly",
    priority: 0.65,
  },
  {
    path: "/account",
    title: "Account Settings and Locked Backup | deRoute",
    description:
      "Manage the words deRoute always hides before messages leave your device, export or import your locked backup, and sign out of your private AI chat in one place.",
    breadcrumb: "Account",
    lastModified: "2026-11-03",
    changeFrequency: "monthly",
    priority: 0.6,
  },
];

export function pageForPath(path: string): SeoPage {
  const page = SEO_PAGES.find((p) => p.path === path);
  if (!page) throw new Error(`No SEO entry for ${path}`);
  return page;
}

export function canonicalUrl(path: string): string {
  return path === "/" ? SITE_URL : `${SITE_URL}${path}`;
}

export const OG_IMAGE_ALT =
  "deRoute private AI routing diagram: your browser checks the sealed computer, hides personal details and sends only a locked message";

export function pageMetadata(path: string): Metadata {
  const page = pageForPath(path);
  const url = canonicalUrl(path);
  return {
    title: { absolute: page.title },
    description: page.description,
    alternates: { canonical: url },
    openGraph: {
      type: "website",
      url,
      title: page.title,
      description: page.description,
      siteName: SITE_NAME,
      locale: "en_GB",
      images: [
        {
          url: `${SITE_URL}/opengraph-image.png`,
          width: 1200,
          height: 630,
          alt: OG_IMAGE_ALT,
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      title: page.title,
      description: page.description,
      images: [{ url: `${SITE_URL}/twitter-image.png`, alt: OG_IMAGE_ALT }],
    },
  };
}

export function websiteJsonLd() {
  return {
    "@type": "WebSite",
    "@id": `${SITE_URL}/#website`,
    name: SITE_NAME,
    url: `${SITE_URL}/`,
    inLanguage: "en-GB",
    description: pageForPath("/").description,
    publisher: PERSON_REF,
    author: PERSON_REF,
  };
}

export function homeJsonLd() {
  return {
    "@context": "https://schema.org",
    "@graph": [
      websiteJsonLd(),
      {
        "@type": "SoftwareApplication",
        "@id": `${SITE_URL}/#software`,
        name: SITE_NAME,
        url: `${SITE_URL}/`,
        applicationCategory: "SecurityApplication",
        operatingSystem: "Web",
        description:
          "deRoute is a private AI router and chat. Your browser verifies sealed hardware before your prompt leaves your screen, hides personal details on your device and sends only a locked message to frontier AI models.",
        inLanguage: "en-GB",
        author: PERSON_REF,
        creator: PERSON_REF,
        award: AWARD,
        sameAs: ["https://github.com/thepigdestroyer/drouter"],
        mainEntityOfPage: { "@id": `${SITE_URL}/#webpage` },
      },
      {
        "@type": "WebPage",
        "@id": `${SITE_URL}/#webpage`,
        url: `${SITE_URL}/`,
        name: pageForPath("/").title,
        description: pageForPath("/").description,
        inLanguage: "en-GB",
        isPartOf: { "@id": `${SITE_URL}/#website` },
        about: { "@id": `${SITE_URL}/#software` },
        author: PERSON_REF,
      },
    ],
  };
}

export function subPageJsonLd(path: string) {
  const page = pageForPath(path);
  const url = canonicalUrl(path);
  return {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "WebPage",
        "@id": `${url}#webpage`,
        url,
        name: page.title,
        description: page.description,
        inLanguage: "en-GB",
        isPartOf: { "@id": `${SITE_URL}/#website` },
        author: PERSON_REF,
        breadcrumb: { "@id": `${url}#breadcrumb` },
      },
      {
        "@type": "BreadcrumbList",
        "@id": `${url}#breadcrumb`,
        itemListElement: [
          {
            "@type": "ListItem",
            position: 1,
            name: "deRoute",
            item: `${SITE_URL}/`,
          },
          {
            "@type": "ListItem",
            position: 2,
            name: page.breadcrumb,
            item: url,
          },
        ],
      },
    ],
  };
}

export function serializeJsonLd(data: unknown): string {
  return JSON.stringify(data).replace(/</g, "\\u003c");
}
