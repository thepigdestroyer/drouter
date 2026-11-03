import { JsonLd } from "@/components/json-ld";
import { LandingPage } from "@/components/landing/landing-page";
import type { Metadata } from "next";
import { homeJsonLd, pageMetadata } from "@/lib/seo";

export const metadata: Metadata = pageMetadata("/");

export default function Home() {
  return (
    <>
      <JsonLd data={homeJsonLd()} />
      <LandingPage />
    </>
  );
}
