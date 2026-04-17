"use client";

import { cn } from "@/lib/utils/cn";

export interface Tab<Id extends string = string> {
  id: Id;
  label: string;
}

interface TabBarProps<Id extends string> {
  tabs: Tab<Id>[];
  activeTab: Id;
  onChange: (id: Id) => void;
  className?: string;
}

export function TabBar<Id extends string>({
  tabs,
  activeTab,
  onChange,
  className,
}: TabBarProps<Id>) {
  return (
    <div
      className={cn(
        "flex items-center gap-1 border-b border-db-border",
        className,
      )}
    >
      {tabs.map((tab) => (
        <button
          key={tab.id}
          onClick={() => onChange(tab.id)}
          className={cn(
            "px-4 py-2.5 text-sm font-medium transition-colors relative",
            activeTab === tab.id
              ? "text-db-teal-light"
              : "text-db-muted hover:text-db-text",
          )}
        >
          {tab.label}
          {activeTab === tab.id && (
            <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-db-teal-light" />
          )}
        </button>
      ))}
    </div>
  );
}
