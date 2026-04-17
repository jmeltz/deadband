"use client";

import { useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { TabBar } from "@/components/ui/TabBar";
import { DatabaseTab } from "./_tabs/DatabaseTab";
import { IntegrationsTab } from "./_tabs/IntegrationsTab";

type TabId = "database" | "integrations";

const tabs = [
  { id: "database" as const, label: "Database" },
  { id: "integrations" as const, label: "Integrations" },
];

function SettingsContent() {
  const searchParams = useSearchParams();
  const initial = searchParams.get("tab");
  const [activeTab, setActiveTab] = useState<TabId>(
    initial === "integrations" ? "integrations" : "database",
  );

  return (
    <div className="max-w-5xl space-y-4">
      <TabBar tabs={tabs} activeTab={activeTab} onChange={setActiveTab} />
      {activeTab === "database" && <DatabaseTab />}
      {activeTab === "integrations" && <IntegrationsTab />}
    </div>
  );
}

export default function SettingsPage() {
  return (
    <Suspense>
      <SettingsContent />
    </Suspense>
  );
}
