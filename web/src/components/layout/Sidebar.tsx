"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils/cn";

type NavItem = {
  href: string;
  label: string;
  icon: (p: { className?: string }) => React.ReactElement;
};

// v0.5 nav: Dashboard, Scan, Assets, Report, Settings. Other surfaces
// (sites, acl, posture, advisories) are reachable via direct URL but
// hidden from the sidebar pending the enterprise-pivot decision.
const nav: NavItem[] = [
  { href: "/", label: "Dashboard", icon: DashboardIcon },
  { href: "/scan", label: "Scan", icon: ScanIcon },
  { href: "/assets", label: "Assets", icon: AssetsIcon },
  { href: "/report", label: "Report", icon: ReportIcon },
  { href: "/settings", label: "Settings", icon: SettingsIcon },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-56 shrink-0 border-r border-db-border bg-db-bg flex flex-col">
      <div className="px-4 py-5 border-b border-db-border">
        <Link href="/" className="flex items-center gap-2.5">
          <img src="/logo.png" alt="deadband" className="w-8 h-8 shrink-0" />
          <div>
            <h1 className="font-heading text-base font-semibold text-db-text leading-tight">
              deadband
            </h1>
            <p className="text-[10px] text-db-muted font-mono tracking-wider uppercase">
              OT Asset & Vuln Scanner
            </p>
          </div>
        </Link>
      </div>

      <nav className="flex-1 px-2 py-3 space-y-0.5">
        {nav.map(({ href, label, icon: Icon }) => {
          const active =
            href === "/" ? pathname === "/" : pathname.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                "flex items-center gap-2.5 px-3 py-2 rounded-sm text-sm transition-colors",
                active
                  ? "bg-db-teal-dim text-db-teal-light font-medium nav-active-glow"
                  : "text-db-muted hover:text-db-text hover:bg-db-surface",
              )}
            >
              <Icon className="w-4 h-4 shrink-0" />
              {label}
            </Link>
          );
        })}
      </nav>

      <div className="px-4 py-3 border-t border-db-border">
        <p className="text-[10px] text-db-muted font-mono">
          READ-ONLY — no OT writes
        </p>
      </div>
    </aside>
  );
}

function DashboardIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="1" y="1" width="6" height="6" rx="1" />
      <rect x="9" y="1" width="6" height="6" rx="1" />
      <rect x="1" y="9" width="6" height="6" rx="1" />
      <rect x="9" y="9" width="6" height="6" rx="1" />
    </svg>
  );
}

function ScanIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <circle cx="7" cy="7" r="4.5" />
      <path d="M11 11l3.5 3.5" strokeLinecap="round" />
    </svg>
  );
}

function AssetsIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="2" y="1" width="12" height="4" rx="1" />
      <rect x="2" y="6" width="12" height="4" rx="1" />
      <rect x="2" y="11" width="12" height="4" rx="1" />
      <circle cx="5" cy="3" r="0.75" fill="currentColor" stroke="none" />
      <circle cx="5" cy="8" r="0.75" fill="currentColor" stroke="none" />
      <circle cx="5" cy="13" r="0.75" fill="currentColor" stroke="none" />
    </svg>
  );
}

function ReportIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M3 1h7l3 3v11H3V1z" />
      <path d="M10 1v3h3" />
      <path d="M5 8h6M5 11h6M5 5h2" strokeLinecap="round" />
    </svg>
  );
}

function SettingsIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <circle cx="8" cy="8" r="2.5" />
      <path d="M8 1v2M8 13v2M1 8h2M13 8h2M3 3l1.5 1.5M11.5 11.5L13 13M13 3l-1.5 1.5M4.5 11.5L3 13" />
    </svg>
  );
}
