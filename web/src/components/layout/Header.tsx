"use client";

import { usePathname } from "next/navigation";

const titles: Record<string, string> = {
  "/": "Dashboard",
  "/devices": "Devices",
  "/advisories": "Advisories",
  "/advisories/detail": "Advisory Detail",
  "/check": "Vulnerability Check",
  "/discover": "Network Discovery",
  "/diff": "Inventory Diff",
  "/settings": "Settings",
};

export function Header() {
  const pathname = usePathname();
  const title =
    titles[pathname] ||
    Object.entries(titles).find(([k]) => k !== "/" && pathname.startsWith(k))?.[1] ||
    "deadband";

  return (
    <header className="h-12 shrink-0 border-b border-db-border bg-db-surface/50 flex items-center px-6">
      <h2 className="font-heading text-sm font-semibold text-db-text">
        {title}
      </h2>
    </header>
  );
}
