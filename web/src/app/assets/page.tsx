"use client";

import { useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { InventoryTab } from "./_tabs/InventoryTab";
import { DiscoverTab } from "./_tabs/DiscoverTab";
import { HistoryTab } from "./_tabs/HistoryTab";
import { CompareTab } from "./_tabs/CompareTab";

type Tab = "inventory" | "discover" | "history" | "compare";

const tabs: { id: Tab; label: string }[] = [
  { id: "inventory", label: "Inventory" },
  { id: "discover", label: "Discover" },
  { id: "history", label: "History & Schedules" },
  { id: "compare", label: "Compare" },
];

function AssetsContent() {
  const searchParams = useSearchParams();
  const initial = searchParams.get("tab");
  const [activeTab, setActiveTab] = useState<Tab>(
    initial === "discover" || initial === "history" || initial === "compare"
      ? initial
      : "inventory",
  );

  return (
    <div className="max-w-7xl space-y-4">
      {/* Tab bar */}
      <div className="flex items-center gap-1 border-b border-db-border">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2.5 text-sm font-medium transition-colors relative ${
              activeTab === tab.id
                ? "text-db-teal-light"
                : "text-db-muted hover:text-db-text"
            }`}
          >
            {tab.label}
            {activeTab === tab.id && (
              <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-db-teal-light" />
            )}
          </button>
        ))}
      </div>

      {activeTab === "inventory" && (
        <InventoryTab onDiscover={() => setActiveTab("discover")} />
      )}
      {activeTab === "discover" && (
        <DiscoverTab onImported={() => setActiveTab("inventory")} />
      )}
      {activeTab === "history" && <HistoryTab />}
      {activeTab === "compare" && <CompareTab />}
    </div>
  );
}

export default function AssetsPage() {
  return (
    <Suspense>
      <AssetsContent />
    </Suspense>
  );
}
