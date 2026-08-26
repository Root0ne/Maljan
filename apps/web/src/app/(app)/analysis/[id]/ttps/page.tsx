"use client";

import { useEffect } from "react";
import { useParams, useRouter } from "next/navigation";

// The ATT&CK and TTPS tabs were merged into a single ATT&CK tab at
// /capabilities (confidence heatmap on top + searchable technique browser
// below). This route is kept only so existing /ttps deep links redirect
// there instead of 404-ing.
export default function TtpsRedirect() {
  const router = useRouter();
  const params = useParams();
  const id = params.id as string;

  useEffect(() => {
    if (id) router.replace(`/analysis/${id}/capabilities`);
  }, [id, router]);

  return (
    <div className="p-4 text-sm text-text-secondary">
      Redirecting to the ATT&amp;CK tab&hellip;
    </div>
  );
}
