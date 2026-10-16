/**
 * The plugin allow-list editor: every installed plugin per kind with its
 * package, version and what its metadata says of it, the API's own load
 * apart from it, the tick that stages its entry, and the entries no installed
 * package declares, drawn from the shapes the API serves.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import served from "@/test-fixtures/settings-schema.json";
import type { InstalledPlugin, PluginsListing, SettingsSchema } from "@/types/settings";
import { PluginAllowListView, type PluginAllowListViewProps } from "../PluginAllowListEditor";
import {
  PLUGIN_ALLOW_LIST_KEY,
  TRUST_NOTE,
  WORKER_NOTE,
  absentEntries,
  allowListOf,
  apiStatus,
  pluginRows,
  pluginStatus,
  withEntry,
} from "../pluginAllowList";
import { groupsBySection, pathForKey } from "../sections";

const schema = served as unknown as SettingsSchema;

function plugin(overrides: Partial<InstalledPlugin>): InstalledPlugin {
  return {
    name: "acme",
    entry: "static:acme",
    distribution: "maljan-acme",
    version: "1.2.3",
    allowed: false,
    state: "not_allowed",
    error: "",
    api_state: "",
    api_error: "",
    ...overrides,
  };
}

const LISTING: PluginsListing = {
  allow_list_key: PLUGIN_ALLOW_LIST_KEY,
  kinds: [
    {
      kind: "llm",
      group: "maljan.llm_providers",
      title: "LLM providers",
      plugins: [
        plugin({
          name: "acme_llm",
          entry: "llm:acme_llm",
          allowed: true,
          state: "allowed",
          api_state: "failed",
          api_error: "ImportError: no client",
        }),
      ],
      allowed_absent: [],
    },
    {
      kind: "static",
      group: "maljan.static_providers",
      title: "Static analysis providers",
      plugins: [
        plugin({ allowed: true, state: "allowed" }),
        plugin({
          name: "ghidra",
          entry: "static:ghidra",
          distribution: "ghidra-fork",
          state: "refused",
          error: "'ghidra' is a built-in static provider, and the loader never registers a plugin under a built-in id",
        }),
      ],
      allowed_absent: [],
    },
    { kind: "sandbox", group: "maljan.sandbox_providers", title: "Sandbox providers", plugins: [], allowed_absent: [] },
    {
      kind: "memory",
      group: "maljan.memory_backends",
      title: "Memory backends",
      plugins: [plugin({ name: "vectorhub", entry: "memory:vectorhub", allowed: true, state: "allowed", api_state: "loaded" })],
      allowed_absent: ["gone"],
    },
  ],
};

/** The tick box of one plugin, as rendered. */
function boxOf(html: string, entry: string): string {
  const found = new RegExp(`<input[^>]*aria-label="Allow ${entry}"[^>]*/>`).exec(html);
  expect(found, entry).not.toBeNull();
  return found![0];
}

function render(props: Partial<PluginAllowListViewProps>): string {
  return renderToStaticMarkup(
    createElement(PluginAllowListView, {
      listing: LISTING,
      error: null,
      list: ["llm:acme_llm", "static:acme", "memory:vectorhub", "memory:gone"],
      editable: true,
      onChange: () => undefined,
      ...props,
    })
  );
}

describe("the served setting", () => {
  it("is one list leaf the plugin editor draws, under Platform", () => {
    const entry = schema.groups.flatMap((g) => g.entries).find((e) => e.key === PLUGIN_ALLOW_LIST_KEY);
    expect(entry).toMatchObject({
      type: "list",
      editor: "plugin_allow_list",
      group: "plugins",
      editable: true,
      title: "Allowed plugins",
    });
    const platform = groupsBySection(schema).find((s) => s.section.key === "platform");
    expect(platform?.groups.map((g) => g.key)).toContain("plugins");
    expect(pathForKey(schema, PLUGIN_ALLOW_LIST_KEY)).toBe("/settings/configuration/platform/plugins");
  });
});

describe("the allow-list", () => {
  it("is read as names only", () => {
    expect(allowListOf(["llm:acme", 3, null, "static:x"])).toEqual(["llm:acme", "static:x"]);
    expect(allowListOf(null)).toEqual([]);
    expect(allowListOf("llm:acme")).toEqual([]);
  });

  it("keeps the other entries in their order when one is ticked or unticked", () => {
    const list = ["llm:a", "static:b", "memory:c"];
    expect(withEntry(list, "sandbox:d", true)).toEqual(["llm:a", "static:b", "memory:c", "sandbox:d"]);
    expect(withEntry(list, "static:b", false)).toEqual(["llm:a", "memory:c"]);
    expect(withEntry(list, "static:b", true)).toEqual(["llm:a", "memory:c", "static:b"]);
  });

  it("names the entries no installed package declares", () => {
    expect(absentEntries(LISTING, ["memory:gone", "static:acme", "llm:other"])).toEqual([
      "memory:gone",
      "llm:other",
    ]);
  });
});

describe("a plugin's status", () => {
  it("says what its metadata says, against the list the next apply leaves", () => {
    const allowed = plugin({ allowed: true, state: "allowed" });
    expect(pluginStatus(allowed, true)).toEqual({ text: "Allowed", tone: "ok" });
    expect(pluginStatus(allowed, false).text).toBe("Not allowed once the change is applied");
    expect(pluginStatus(plugin({}), true).text).toBe("Allowed once the change is applied");
    expect(pluginStatus(plugin({}), false).text).toBe("Not allowed; its code is not loaded");
    expect(pluginStatus(plugin({ state: "refused", error: "two packages" }), true)).toEqual({
      text: "Refused: two packages",
      tone: "error",
    });
  });

  it("names the API's own load as the API's, and nothing as a worker's", () => {
    expect(apiStatus(plugin({ api_state: "loaded" }))).toEqual({ text: "Loaded in the API", tone: "ok" });
    expect(apiStatus(plugin({ api_state: "failed", api_error: "ImportError: x" }))).toEqual({
      text: "Failed in the API: ImportError: x",
      tone: "error",
    });
    expect(apiStatus(plugin({})).text).toBe("Not loaded in the API");
    expect(WORKER_NOTE).toContain("written to the worker's log");
  });

  it("is ticked from the staged list, not from what is saved", () => {
    const [acme, ghidra] = pluginRows(LISTING.kinds[1], []);
    expect(acme).toMatchObject({ allowed: false, status: "Not allowed once the change is applied" });
    expect(ghidra).toMatchObject({ allowed: false, refused: true });
  });
});

describe("the editor", () => {
  it("draws every kind with each plugin's package, version, status and the API's own load", () => {
    const html = render({});
    expect(TRUST_NOTE).toContain("Nothing installed is loaded until it is allowed here.");
    expect(html).toContain("Nothing installed is loaded until it is allowed here.");
    expect(html).toContain("written to the worker&#x27;s log");
    for (const title of ["LLM providers", "Static analysis providers", "Sandbox providers", "Memory backends"]) {
      expect(html).toContain(title);
    }
    expect(html).toContain("maljan.static_providers");
    expect(html).toContain("maljan-acme");
    expect(html).toContain("1.2.3");
    expect(html).toContain("Failed in the API: ImportError: no client");
    expect(html).toContain("Loaded in the API");
    expect(html).toContain("Refused: &#x27;ghidra&#x27; is a built-in static provider");
    expect(html).toContain("No installed package declares one.");
  });

  it("ticks the allowed plugins and holds a refused one unticked", () => {
    const html = render({});
    const acme = boxOf(html, "static:acme");
    expect(acme).toContain('checked=""');
    expect(acme).not.toContain("disabled");
    const ghidra = boxOf(html, "static:ghidra");
    expect(ghidra).toContain('disabled=""');
    expect(ghidra).not.toContain("checked");
  });

  it("offers to remove an entry no installed package declares", () => {
    const html = render({});
    expect(html).toContain('data-testid="plugin-allow-list-absent"');
    expect(html).toContain("memory:gone");
    expect(html).toContain("Remove");
    expect(render({ list: ["static:acme"] })).not.toContain("plugin-allow-list-absent");
  });

  it("says when the list cannot be read, and while it is read", () => {
    expect(render({ listing: null, error: "Admin role required" })).toContain(
      "The installed plugins could not be listed: Admin role required"
    );
    expect(render({ listing: null })).toContain("Reading the installed plugins");
  });

  it("changes nothing for a reader who may not edit", () => {
    const acme = boxOf(render({ editable: false }), "static:acme");
    expect(acme).toContain('checked=""');
    expect(acme).toContain('disabled=""');
  });
});
