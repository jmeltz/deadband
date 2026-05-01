"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils/cn";
import { api } from "@/lib/api";

type LinkItem = {
  kind: "link";
  href: string;
  label: string;
  icon: (p: { className?: string }) => React.ReactElement;
};

type ActionItem = {
  kind: "action";
  label: string;
  icon: (p: { className?: string }) => React.ReactElement;
  onClick: () => void | Promise<void>;
  pending?: boolean;
};

type NavItem = LinkItem | ActionItem;

// v0.5 nav: Dashboard, Scan, Report (action — triggers HTML download),
// Settings. Other surfaces (assets, sites, acl, posture, advisories) are
// reachable via direct URL but hidden from the sidebar pending the
// enterprise-pivot decision.
export function Sidebar() {
  const pathname = usePathname();
  const [exporting, setExporting] = useState(false);

  const handleReport = async () => {
    if (exporting) return;
    setExporting(true);
    try {
      const { blob, filename } = await api.exportHTMLReport({});
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch {
      // surfaced on the Dashboard's Export button; quiet here
    } finally {
      setExporting(false);
    }
  };

  const nav: NavItem[] = [
    { kind: "link", href: "/", label: "Dashboard", icon: DashboardIcon },
    { kind: "link", href: "/scan", label: "Scan", icon: ScanIcon },
    { kind: "action", label: "Report", icon: ReportIcon, onClick: handleReport, pending: exporting },
    { kind: "link", href: "/settings", label: "Settings", icon: SettingsIcon },
  ];

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
        {nav.map((item) => {
          if (item.kind === "action") {
            const Icon = item.icon;
            return (
              <button
                key={item.label}
                onClick={item.onClick}
                disabled={item.pending}
                className={cn(
                  "w-full flex items-center gap-2.5 px-3 py-2 rounded-sm text-sm transition-colors",
                  "text-db-muted hover:text-db-text hover:bg-db-surface",
                  item.pending && "opacity-60",
                )}
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span className="flex-1 text-left">{item.label}</span>
                {item.pending && (
                  <span className="text-[10px] text-db-muted">…</span>
                )}
              </button>
            );
          }

          const { href, label, icon: Icon } = item;
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
