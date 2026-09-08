"use client";

import { Suspense } from "react";
import { useParams } from "next/navigation";
import GuidePage from "../GuidePage";
import { guideById } from "../guides";

/** One guide, by route segment. `GuidePage` reads `?step=`, so it renders
 *  inside a Suspense boundary. */
export default function SetupGuideRoute() {
  const params = useParams<{ guide: string }>();
  const id = Array.isArray(params.guide) ? params.guide[0] : params.guide;
  const guide = id ? guideById(id) : undefined;

  if (!guide) {
    return <p role="alert">No such setup guide.</p>;
  }
  return (
    <Suspense fallback={<div className="text-sm text-text-secondary">Loading guide…</div>}>
      <GuidePage guide={guide} />
    </Suspense>
  );
}
