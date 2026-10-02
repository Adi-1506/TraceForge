import { useEffect, useState } from "react";

export const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function get(path) {
  const res = await fetch(`${API_URL}${path}`);
  if (!res.ok) throw new Error(`${res.status} ${path}`);
  return res.json();
}

export const api = {
  stats: () => get("/stats"),
  devices: () => get("/devices"),
  device: (id) => get(`/devices/${id}`),
  timeline: (id) => get(`/devices/${id}/timeline`),
  riskHistory: (id) => get(`/risk-scores/${id}`),
  incidents: () => get("/incidents"),
  incident: (id) => get(`/incidents/${id}`),
};

// Re-runs `load` every `ms`; returns { data, error }. `key` resets the data when the target changes.
export function usePolling(load, key, ms = 3000) {
  const [state, setState] = useState({ data: null, error: null });

  useEffect(() => {
    let alive = true;
    setState({ data: null, error: null });
    const tick = async () => {
      try {
        const data = await load();
        if (alive) setState({ data, error: null });
      } catch (error) {
        if (alive) setState((s) => ({ ...s, error }));
      }
    };
    tick();
    const timer = setInterval(tick, ms);
    return () => {
      alive = false;
      clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, ms]);

  return state;
}

export const formatTime = (iso) =>
  new Date(/[zZ]|[+-]\d\d:\d\d$/.test(iso) ? iso : `${iso}Z`).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
