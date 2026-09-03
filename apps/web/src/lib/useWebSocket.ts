"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import type { WSEvent } from "@/types";

/**
 * Where the socket dials.
 *
 * NEXT_PUBLIC_WS_URL is the override; the default is derived from the API base
 * rather than written out again. The two used to be independent literals —
 * `ws://localhost:8000` here against `http://127.0.0.1:8000` in api.ts — which
 * are *different origins*, so an unconfigured deployment could reach the API
 * and silently fail to reach the socket, and a test harness had to remember to
 * pin two variables instead of one.
 */
function defaultWsBase(): string {
  const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
  return api.replace(/^http/, "ws");
}

const WS_BASE = process.env.NEXT_PUBLIC_WS_URL || defaultWsBase();

/**
 * Reconnect schedule (audit follow-up 2026-05-19).
 *
 * The previous implementation reconnected on a fixed 3-second timer. That
 * hammered the API on long outages (a 5-minute backend restart produced
 * 100 reconnect attempts) and gave the UI no signal that a retry was
 * pending. We now use exponential backoff with full jitter, capped at
 * ``MAX_DELAY_MS``. Resets to the base delay on every successful
 * ``onopen`` so transient blips do not bias subsequent retries.
 */
const BASE_DELAY_MS = 1_000;
const MAX_DELAY_MS = 30_000;

function backoffDelay(attempt: number): number {
  // Full jitter (AWS architecture blog): pick a random value between 0
  // and the exponential ceiling. Avoids thundering-herd reconnects when
  // many tabs / users come back online together after a backend outage.
  const ceiling = Math.min(MAX_DELAY_MS, BASE_DELAY_MS * 2 ** attempt);
  return Math.floor(Math.random() * ceiling);
}

export function useWebSocket(jobId: string | null) {
  const [events, setEvents] = useState<WSEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const attemptRef = useRef(0);
  const cancelledRef = useRef(false);
  // Wave 10 W10-LINT-DEBT-02 (2026-05-30): ``connect`` referenced itself
  // inside the ws.onclose reconnect handler, which the ESLint
  // ``react-hooks/immutability`` rule flags as access-before-declared
  // (the inner closure captures whichever ``connect`` exists at
  // useCallback-construction time, not the latest one — fine for the
  // current ``[jobId]`` dep set, but a stale-closure trap if a future
  // dep is added). Indirecting through a ref means the timeout fires
  // through whatever ``connect`` is current at the moment the timer
  // ticks, not what was captured when the WebSocket opened.
  const connectRef = useRef<() => void>(() => {});

  const connect = useCallback(() => {
    if (!jobId || cancelledRef.current) return;

    const token =
      typeof window !== "undefined"
        ? localStorage.getItem("access_token")
        : null;

    const url = `${WS_BASE}/ws/analysis/${jobId}`;
    const ws = token
      ? new WebSocket(url, ["maljan.v1", `maljan.v1.${token}`])
      : new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      // A successful open returns the schedule to its base delay. Without
      // this, a long-lived connection that drops once gets bumped through
      // the same attempt counter as a server that's been down for an hour.
      attemptRef.current = 0;
    };

    ws.onmessage = (evt) => {
      try {
        const event: WSEvent = JSON.parse(evt.data);
        if (event.type !== "heartbeat" && event.type !== "pong") {
          setEvents((prev) => [...prev, event]);
        }
      } catch {
        /* ignore malformed messages */
      }
    };

    ws.onclose = (event) => {
      setConnected(false);
      /* Don't auto-reconnect on auth/policy failure (1008) — credential
         needs to be refreshed first. */
      if (event.code === 1008) return;
      if (cancelledRef.current) return;
      const delay = backoffDelay(attemptRef.current);
      attemptRef.current += 1;
      reconnectTimerRef.current = setTimeout(() => connectRef.current(), delay);
    };

    ws.onerror = () => ws.close();
  }, [jobId]);

  // Keep the ref pointed at the latest ``connect`` so the reconnect
  // timeout always invokes the current closure.
  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  useEffect(() => {
    cancelledRef.current = false;
    attemptRef.current = 0;
    connect();
    return () => {
      cancelledRef.current = true;
      if (reconnectTimerRef.current !== null) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      wsRef.current?.close();
    };
  }, [connect]);

  return { events, connected };
}
