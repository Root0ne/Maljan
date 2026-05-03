"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import type { WSEvent } from "@/types";

const WS_BASE = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000";

export function useWebSocket(jobId: string | null) {
  const [events, setEvents] = useState<WSEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  const connect = useCallback(() => {
    if (!jobId) return;

    const ws = new WebSocket(`${WS_BASE}/ws/analysis/${jobId}`);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);

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

    ws.onclose = () => {
      setConnected(false);
      /* auto-reconnect after 3s */
      setTimeout(() => connect(), 3000);
    };

    ws.onerror = () => ws.close();
  }, [jobId]);

  useEffect(() => {
    connect();
    return () => {
      wsRef.current?.close();
    };
  }, [connect]);

  return { events, connected };
}
