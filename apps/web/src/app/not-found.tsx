import Link from "next/link";

/**
 * A5 (dev audit 2026-09-06): an unknown URL used to render Next's built-in 404
 * — no chrome, no link, nothing but the browser's Back button to get out of.
 * This one is still deliberately outside the app shell: the shell mounts
 * `AuthProvider`, which redirects an unauthenticated visitor to /login, and a
 * mistyped URL is not a reason to end someone's session. So it carries its own
 * way back instead.
 */
export default function NotFound() {
  return (
    <main className="min-h-screen flex items-center justify-center p-6">
      <div className="bg-bg-surface border border-border rounded p-8 text-center max-w-md">
        <p className="text-xs uppercase tracking-wider text-text-muted mb-2">Error 404</p>
        <h1 className="text-lg font-semibold text-text-primary mb-1">Page not found</h1>
        <p className="text-sm text-text-secondary mb-5">
          The page you asked for does not exist. It may have been moved, or the link
          that brought you here may be out of date.
        </p>
        <div className="flex items-center justify-center gap-4">
          <Link href="/dashboard" className="text-sm text-accent-strong hover:underline">
            Back to dashboard
          </Link>
          <Link href="/jobs" className="text-sm text-text-secondary hover:underline">
            Analysis jobs
          </Link>
        </div>
      </div>
    </main>
  );
}
