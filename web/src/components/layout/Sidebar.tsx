"use client";

import { useSyncExternalStore } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils/cn";

type LeafItem = {
  href: string;
  label: string;
  icon: (p: { className?: string }) => React.ReactElement;
};

type GroupItem = {
  label: string;
  icon: (p: { className?: string }) => React.ReactElement;
  children: LeafItem[];
};

type NavItem = LeafItem | GroupItem;

const nav: NavItem[] = [
  { href: "/", label: "Dashboard", icon: DashboardIcon },
  { href: "/assets", label: "Assets", icon: AssetsIcon },
  {
    label: "Network",
    icon: SitesIcon,
    children: [
      { href: "/sites", label: "Sites", icon: SitesIcon },
      { href: "/acl", label: "ACL Policies", icon: ACLIcon },
    ],
  },
  { href: "/posture", label: "Posture", icon: PostureIcon },
  { href: "/advisories", label: "Advisories", icon: AdvisoriesIcon },
  { href: "/settings", label: "Settings", icon: SettingsIcon },
];

const NETWORK_GROUP_KEY = "deadband.sidebar.network";
const NETWORK_GROUP_EVENT = "deadband.sidebar.network.change";

function subscribeNetworkGroup(onChange: () => void) {
  window.addEventListener(NETWORK_GROUP_EVENT, onChange);
  return () => window.removeEventListener(NETWORK_GROUP_EVENT, onChange);
}

function readNetworkGroup(): "open" | "closed" | null {
  try {
    const v = localStorage.getItem(NETWORK_GROUP_KEY);
    return v === "open" || v === "closed" ? v : null;
  } catch {
    return null;
  }
}

export function Sidebar() {
  const pathname = usePathname();
  const networkActive = nav.some(
    (item) =>
      "children" in item &&
      item.children.some((c) => pathname.startsWith(c.href)),
  );

  const stored = useSyncExternalStore(
    subscribeNetworkGroup,
    readNetworkGroup,
    () => null,
  );

  const networkOpen =
    stored === "open" || (stored === null && networkActive);

  const toggleNetwork = () => {
    const next = networkOpen ? "closed" : "open";
    try {
      localStorage.setItem(NETWORK_GROUP_KEY, next);
    } catch {
      // localStorage unavailable
    }
    window.dispatchEvent(new Event(NETWORK_GROUP_EVENT));
  };

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
          if ("children" in item) {
            const Icon = item.icon;
            const anyActive = item.children.some((c) =>
              pathname.startsWith(c.href),
            );
            return (
              <div key={item.label}>
                <button
                  onClick={toggleNetwork}
                  className={cn(
                    "w-full flex items-center gap-2.5 px-3 py-2 rounded-sm text-sm transition-colors",
                    anyActive
                      ? "text-db-text font-medium"
                      : "text-db-muted hover:text-db-text hover:bg-db-surface",
                  )}
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  <span className="flex-1 text-left">{item.label}</span>
                  <span className="text-[10px] text-db-muted">
                    {networkOpen ? "\u25BC" : "\u25B6"}
                  </span>
                </button>
                {networkOpen && (
                  <div className="mt-0.5 ml-3 pl-3 border-l border-db-border space-y-0.5">
                    {item.children.map(({ href, label, icon: ChildIcon }) => {
                      const active = pathname.startsWith(href);
                      return (
                        <Link
                          key={href}
                          href={href}
                          className={cn(
                            "flex items-center gap-2.5 px-3 py-1.5 rounded-sm text-sm transition-colors",
                            active
                              ? "bg-db-teal-dim text-db-teal-light font-medium nav-active-glow"
                              : "text-db-muted hover:text-db-text hover:bg-db-surface",
                          )}
                        >
                          <ChildIcon className="w-3.5 h-3.5 shrink-0" />
                          {label}
                        </Link>
                      );
                    })}
                  </div>
                )}
              </div>
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

function AdvisoriesIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M8 1L14 13H2L8 1z" />
      <path d="M8 6v3M8 11v.5" />
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

function SitesIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M8 1L2 5v6l6 4 6-4V5L8 1z" />
      <circle cx="8" cy="8" r="2" />
    </svg>
  );
}

function PostureIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M8 1L2 4v4c0 3.5 2.5 6.2 6 7 3.5-.8 6-3.5 6-7V4L8 1z" />
      <circle cx="8" cy="7" r="2" />
      <path d="M8 9v2" />
    </svg>
  );
}

function ACLIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="1" y="3" width="14" height="10" rx="1" />
      <path d="M1 6h14M5 6v7M11 6v7" />
      <path d="M3 9h1M7 9h2M13 9h-1" />
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
