/**
 * The routes that moved (`next.config.ts`), checked against the app's own
 * pages: every redirect lands on a page that exists, keeps its query, and a
 * chain (an old preview link to a retired tab) ends on a page within two
 * hops, never in a loop or on a 404.
 */

import { existsSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import nextConfig from "../../../next.config";
import { ANALYSIS_TABS } from "@/components/analysis/overview";

const APP = path.resolve(__dirname, "../../app/(app)");

interface Redirect {
  source: string;
  destination: string;
  permanent: boolean;
}

async function redirects(): Promise<Redirect[]> {
  return (await nextConfig.redirects!()) as Redirect[];
}

/** The page file a concrete path (`/analysis/j/behaviour`) is served by, or null. */
function pageFor(pathname: string): string | null {
  const parts = pathname.split("/").filter(Boolean);
  let dir = APP;
  for (const part of parts) {
    const literal = path.join(dir, part);
    if (existsSync(literal)) {
      dir = literal;
      continue;
    }
    const dynamic = ["[id]", "[key]"].map((d) => path.join(dir, d)).find((d) => existsSync(d));
    if (!dynamic) return null;
    dir = dynamic;
  }
  const page = path.join(dir, "page.tsx");
  return existsSync(page) ? page : null;
}

/** Where one redirect sends `pathname`, or null when its source does not match. */
function follow(r: Redirect, pathname: string): string | null {
  const names: string[] = [];
  const pattern = r.source
    .split("/")
    .map((seg) => {
      if (seg.startsWith(":") && seg.endsWith("*")) {
        names.push(seg.slice(1, -1));
        return "(.*)";
      }
      if (seg.startsWith(":")) {
        names.push(seg.slice(1));
        return "([^/]+)";
      }
      return seg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    })
    .join("/");
  const match = new RegExp(`^${pattern}$`).exec(pathname);
  if (!match) return null;
  let out = r.destination;
  names.forEach((name, i) => {
    out = out.replace(new RegExp(`:${name}\\*?`), match[i + 1]);
  });
  return out;
}

/** Follow redirects from `start` until a path no redirect matches; the hops taken. */
async function resolve(start: string): Promise<string[]> {
  const all = await redirects();
  const hops = [start];
  let at = start;
  for (let i = 0; i < 5; i++) {
    const bare = at.split(/[?#]/)[0];
    const next = all.map((r) => follow(r, bare)).find((d): d is string => d !== null);
    if (!next) return hops;
    hops.push(next);
    at = next;
  }
  throw new Error(`redirect loop from ${start}: ${hops.join(" -> ")}`);
}

describe("the routes that moved", () => {
  it("are all permanent", async () => {
    for (const r of await redirects()) expect(r.permanent, r.source).toBe(true);
  });

  it("each land on a page that exists", async () => {
    for (const r of await redirects()) {
      const concrete = r.destination.replace(/:id/g, "j").replace(/:key/g, "k").replace(/\/:path\*/, "");
      const bare = concrete.split(/[?#]/)[0];
      expect(pageFor(bare), `${r.source} -> ${r.destination}`).not.toBeNull();
    }
  });

  it("no longer have a page of their own at the old address", async () => {
    for (const r of await redirects()) {
      const concrete = r.source.replace(/:id/g, "j").replace(/:key/g, "k").replace(/\/:path\*/, "/x");
      if (concrete.startsWith("/preview/analysis/j/x")) continue;
      expect(pageFor(concrete), r.source).toBeNull();
    }
  });

  it("keep the query a destination carries", async () => {
    expect(await resolve("/reports")).toEqual(["/reports", "/jobs?status=completed"]);
  });

  it("land a deep link on the block it became", async () => {
    expect(await resolve("/analysis/j/persistence")).toEqual(["/analysis/j/persistence", "/analysis/j/behaviour#persistence"]);
    expect(await resolve("/analysis/j/agent/hunter")).toEqual(["/analysis/j/agent/hunter", "/analysis/j/evidence/agent/hunter"]);
  });

  it("take a preview link to the tab it named, through a retired tab when it named one", async () => {
    expect(await resolve("/preview/analysis/j")).toEqual(["/preview/analysis/j", "/analysis/j"]);
    for (const tab of ANALYSIS_TABS.filter((t) => t.segment)) {
      const hops = await resolve(`/preview/analysis/j/${tab.segment}`);
      expect(hops).toEqual([`/preview/analysis/j/${tab.segment}`, `/analysis/j/${tab.segment}`]);
      expect(pageFor(hops[1]), tab.segment).not.toBeNull();
    }
    const chain = await resolve("/preview/analysis/j/identity");
    expect(chain).toEqual(["/preview/analysis/j/identity", "/analysis/j/identity", "/analysis/j/static#identity"]);
    expect(pageFor(chain[2].split("#")[0])).not.toBeNull();
  });
});
