"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils/cn";

const nav = [
  { href: "/", label: "Dashboard", icon: DashboardIcon },
  { href: "/devices", label: "Devices", icon: DevicesIcon },
  { href: "/advisories", label: "Advisories", icon: AdvisoriesIcon },
  { href: "/check", label: "Check", icon: CheckIcon },
  { href: "/discover", label: "Discover", icon: DiscoverIcon },
  { href: "/diff", label: "Diff", icon: DiffIcon },
  { href: "/settings", label: "Settings", icon: SettingsIcon },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-56 shrink-0 border-r border-db-border bg-db-bg flex flex-col">
      <div className="px-4 py-5 border-b border-db-border">
        <Link href="/" className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded bg-db-teal flex items-center justify-center">
            <span className="font-heading text-sm font-bold text-white">db</span>
          </div>
          <div>
            <h1 className="font-heading text-base font-semibold text-db-text leading-tight">
              deadband
            </h1>
            <p className="text-[10px] text-db-muted font-mono tracking-wider uppercase">
              ICS Vulnerability Scanner
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
                "flex items-center gap-2.5 px-3 py-2 rounded-md text-sm transition-colors",
                active
                  ? "bg-db-teal-dim text-db-teal-light font-medium"
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

// Minimal inline SVG icons
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

function DevicesIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="2" y="3" width="12" height="8" rx="1" />
      <path d="M5 14h6M8 11v3" />
    </svg>
  );
}

function AdvisoriesIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M8 1L14 13H2L8 1z" />
      <path d="M8 6v3M8 11v.5" />
    </svg>
  );
}

function CheckIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <circle cx="8" cy="8" r="6.5" />
      <path d="M5 8l2 2 4-4" />
    </svg>
  );
}

function DiscoverIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <circle cx="7" cy="7" r="5" />
      <path d="M11 11l3.5 3.5" />
    </svg>
  );
}

function DiffIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M4 1v14M12 1v14M1 8h14" />
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
