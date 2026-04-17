"use client";

import { usePathname } from "next/navigation";

const titles: Record<string, string> = {
  "/": "Dashboard",
  "/assets": "Assets",
  "/assets/detail": "Asset Detail",
  "/advisories": "Advisories",
  "/posture": "Posture",
  "/sites": "Sites",
  "/acl": "ACL",
  "/settings": "Settings",
};

export function Header() {
  const pathname = usePathname();
  const title =
    titles[pathname] ||
    Object.entries(titles).find(([k]) => k !== "/" && pathname.startsWith(k))?.[1] ||
    "deadband";

  return (
    <header className="h-12 shrink-0 border-b header-border-glow bg-db-surface/50 flex items-center px-6">
      <h2 className="font-heading text-sm font-semibold text-db-text">
        {title}
      </h2>
    </header>
  );
}
