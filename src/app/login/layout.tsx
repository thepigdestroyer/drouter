import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Passphrase Vault",
  description:
    "Derive client-side vault keys from a 6-word passphrase, manage custom scrub terms that feed the encrypted console, and export or import AES-256-GCM encrypted vault bundles.",
};

export default function LoginLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}
