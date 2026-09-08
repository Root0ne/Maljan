"use client";

import { useAuth } from "@/lib/auth";
import ConfigurationTab from "./ConfigurationTab";

export default function SettingsConfigurationPage() {
  const { user: authUser } = useAuth();
  const isAdmin = authUser?.role === "admin";

  if (!isAdmin) {
    return (
      <div className="text-sm text-text-secondary" role="alert">
        Configuration is available to administrators only (admin role required).
      </div>
    );
  }

  return (
    <div className="max-w-5xl">
      <ConfigurationTab />
    </div>
  );
}
