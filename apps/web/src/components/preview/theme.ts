"use client";

import { useCallback, useEffect, useSyncExternalStore } from "react";
import { THEME_STORAGE_KEY } from "./themeScript";

/**
 * Light or dark for the new analysis page.
 *
 * The reader's own choice wins and is remembered in this browser; without
 * one, the OS setting decides. The page applies it by setting
 * `data-ui-theme` on <html> (globals.css holds the light tokens) and removes
 * the attribute when it unmounts, so every other page keeps today's look.
 * On a full page load `THEME_BOOT_SCRIPT` has set it before the first paint;
 * this hook keeps it in step afterwards.
 */
export type UiTheme = "light" | "dark";

const KEY = THEME_STORAGE_KEY;
const EVENT = "maljan:ui-theme";

export function resolveTheme(stored: string | null, prefersLight: boolean): UiTheme {
  if (stored === "light" || stored === "dark") return stored;
  return prefersLight ? "light" : "dark";
}

/* The choice made in this page view, for a browser that refuses storage. */
let chosen: UiTheme | null = null;

function readStored(): string | null {
  try {
    return window.localStorage.getItem(KEY) ?? chosen;
  } catch {
    return chosen;
  }
}

function snapshot(): UiTheme {
  const prefersLight =
    typeof window.matchMedia === "function" && window.matchMedia("(prefers-color-scheme: light)").matches;
  return resolveTheme(readStored(), prefersLight);
}

function subscribe(onChange: () => void): () => void {
  const media = typeof window.matchMedia === "function" ? window.matchMedia("(prefers-color-scheme: light)") : null;
  media?.addEventListener("change", onChange);
  window.addEventListener(EVENT, onChange);
  window.addEventListener("storage", onChange);
  return () => {
    media?.removeEventListener("change", onChange);
    window.removeEventListener(EVENT, onChange);
    window.removeEventListener("storage", onChange);
  };
}

export function useUiTheme(): [UiTheme, (next: UiTheme) => void] {
  const theme = useSyncExternalStore(subscribe, snapshot, () => "dark" as UiTheme);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.uiTheme = theme;
    return () => {
      delete root.dataset.uiTheme;
    };
  }, [theme]);

  const set = useCallback((next: UiTheme) => {
    chosen = next;
    try {
      window.localStorage.setItem(KEY, next);
    } catch {
      // A browser that refuses storage still switches for this page view.
    }
    window.dispatchEvent(new Event(EVENT));
  }, []);

  return [theme, set];
}
