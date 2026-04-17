"use client";

import { useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { TabBar } from "@/components/ui/TabBar";
import { FindingsTab } from "./_tabs/FindingsTab";
import { FrameworksTab } from "./_tabs/FrameworksTab";

type TabId = "findings" | "frameworks";

const tabs = [
  { id: "findings" as const, label: "Findings" },
  { id: "frameworks" as const, label: "Frameworks" },
];

function PostureContent() {
  const searchParams = useSearchParams();
  const initial = searchParams.get("tab");
  const [activeTab, setActiveTab] = useState<TabId>(
    initial === "frameworks" ? "frameworks" : "findings",
  );

  return (
    <div className="max-w-7xl space-y-4">
      <TabBar tabs={tabs} activeTab={activeTab} onChange={setActiveTab} />
      {activeTab === "findings" && <FindingsTab />}
      {activeTab === "frameworks" && <FrameworksTab />}
    </div>
  );
}

export default function PosturePage() {
  return (
    <Suspense>
      <PostureContent />
    </Suspense>
  );
}
