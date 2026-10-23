import { describe, expect, it, vi } from "vitest";

import type { PaginatedResponse } from "@/lib/api";
import { LIST_PAGE_SIZE, fetchAllPages } from "@/lib/pages";

interface Row {
  id: number;
}
const rowsOf = (n: number, from = 0): Row[] => Array.from({ length: n }, (_, i) => ({ id: from + i }));

/** A list endpoint over `rows`, answering pages the way the API does. */
function endpoint(rows: Row[], total = rows.length) {
  return vi.fn(async (page: number, pageSize: number): Promise<PaginatedResponse<Row>> => ({
    items: rows.slice((page - 1) * pageSize, page * pageSize),
    total,
    page,
    page_size: pageSize,
  }));
}

describe("every row of a paginated list", () => {
  it("reads past the first page until a short page ends the list", async () => {
    const rows = rowsOf(250);
    const fetchPage = endpoint(rows);
    const { items, total } = await fetchAllPages(fetchPage);
    expect(items).toEqual(rows);
    expect(total).toBe(250);
    expect(fetchPage.mock.calls.map(([page]) => page)).toEqual([1, 2, 3]);
    expect(fetchPage.mock.calls.every(([, size]) => size === LIST_PAGE_SIZE)).toBe(true);
  });

  it("asks once for a list that fits on one page", async () => {
    const fetchPage = endpoint(rowsOf(3));
    expect((await fetchAllPages(fetchPage)).items).toHaveLength(3);
    expect(fetchPage).toHaveBeenCalledTimes(1);
  });

  it("does not trust a total that promises more than the list holds", async () => {
    const fetchPage = endpoint(rowsOf(2), 10);
    const { items, total } = await fetchAllPages(fetchPage, { pageSize: 2 });
    expect(items).toHaveLength(2);
    expect(total).toBe(10);
    expect(fetchPage).toHaveBeenCalledTimes(2);
  });

  it("does not stop at a total that undercounts a list that grew", async () => {
    const fetchPage = endpoint(rowsOf(5), 2);
    expect((await fetchAllPages(fetchPage, { pageSize: 2 })).items).toHaveLength(5);
  });

  it("holds a row a shifted page repeats once", async () => {
    // A row inserted at the head between two reads pushes id 1 onto page 2.
    const pages = [[{ id: 0 }, { id: 1 }], [{ id: 1 }, { id: 2 }], [{ id: 3 }]];
    const fetchPage = vi.fn(async (page: number) => ({ items: pages[page - 1] ?? [], total: 4, page, page_size: 2 }));
    const { items } = await fetchAllPages(fetchPage, { pageSize: 2 });
    expect(items.map((r) => r.id)).toEqual([0, 1, 2, 3]);
  });

  it("stops on a full page that adds nothing new, rather than looping", async () => {
    const fetchPage = vi.fn(async (page: number) => ({ items: [{ id: 1 }, { id: 2 }], total: 99, page, page_size: 2 }));
    const { items } = await fetchAllPages(fetchPage, { pageSize: 2 });
    expect(items).toHaveLength(2);
    expect(fetchPage).toHaveBeenCalledTimes(2);
  });

  it("passes a failed page on rather than drawing a partial list as whole", async () => {
    const fetchPage = vi.fn(async (page: number) => {
      if (page === 2) throw new Error("boom");
      return { items: rowsOf(2), total: 4, page, page_size: 2 };
    });
    await expect(fetchAllPages(fetchPage, { pageSize: 2 })).rejects.toThrow("boom");
  });

  it("ends between pages once aborted", async () => {
    const controller = new AbortController();
    const fetchPage = vi.fn(async (page: number) => {
      controller.abort();
      return { items: rowsOf(2, page * 2), total: 10, page, page_size: 2 };
    });
    await expect(fetchAllPages(fetchPage, { pageSize: 2, signal: controller.signal })).rejects.toThrow();
    expect(fetchPage).toHaveBeenCalledTimes(1);
  });
});
