import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Account settings",
  description:
    "Manage words to always hide before messages leave your device, export or import your locked deRoute backup, and sign out.",
};

export default function AccountLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}
