"use client";

import { useEffect } from "react";
import { useParams, useRouter } from "next/navigation";

/* audit 2026-07-26 (§5 "7 orphan rota"): this route had zero links anywhere in
 * the tab bar and rendered a bare, unlabelled panel when opened directly. The
 * panel itself now lives in ./PipelinePanel and is composed into the PROCESS tab;
 * this file exists only so bookmarked/stale URLs land somewhere coherent
 * instead of on a headless panel. Mirrors the ttps/ redirect. */
export default function PipelineRedirect() {
  const router = useRouter();
  const params = useParams();
  const id = params.id as string;

  useEffect(() => {
    if (id) router.replace(`/analysis/${id}/process`);
  }, [id, router]);

  return (
    <div className="p-4 text-sm text-text-secondary">
      Redirecting to the PROCESS tab&hellip;
    </div>
  );
}
