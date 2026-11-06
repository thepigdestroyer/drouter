import type { MetadataRoute } from "next";
import { INDEXABLE_PAGES, canonicalUrl } from "@/lib/seo";

export default function sitemap(): MetadataRoute.Sitemap {
  return INDEXABLE_PAGES.map((page) => ({
    url: canonicalUrl(page.path),
    lastModified: page.lastModified,
    changeFrequency: page.changeFrequency,
    priority: page.priority,
  }));
}
