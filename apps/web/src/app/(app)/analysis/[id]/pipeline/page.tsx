"use client";

import { useEffect } from "react";
import { useParams, useRouter } from "next/navigation";

/* The run is one conversation now, live and replayed by the same view, so
 * this route has nothing of its own left to draw. It stays so a bookmarked or
 * linked URL lands on the tab that answers what it used to answer. */
export default function PipelineRedirect() {
  const router = useRouter();
  const params = useParams();
  const id = params.id as string;

  useEffect(() => {
    if (id) router.replace(`/analysis/${id}/conversation`);
  }, [id, router]);

  return (
    <div className="p-4 text-sm text-text-secondary">
      Redirecting to the CONVERSATION tab&hellip;
    </div>
  );
}
