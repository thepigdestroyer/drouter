import type { Metadata } from "next";
import { JsonLd } from "@/components/json-ld";
import { pageMetadata, subPageJsonLd } from "@/lib/seo";

const PATH = "/network";

export const metadata: Metadata = pageMetadata(PATH);

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <JsonLd data={subPageJsonLd(PATH)} />
      {children}
    </>
  );
}
