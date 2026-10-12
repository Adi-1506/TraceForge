import { useEffect, useRef, useState } from "react";
import { API_URL, api, formatTime, getToken } from "../api.js";

// Live feed over Server-Sent Events: a bell with unread alerts, a dropdown of recent events, and a
// short-lived notice for every new alert. EventSource cannot send headers, so the token goes in the URL.
export default function LiveAlerts({ onOpenIncident }) {
  const [items, setItems] = useState([]);
  const [unread, setUnread] = useState(0);
  const [open, setOpen] = useState(false);
  const [toasts, setToasts] = useState([]);
  const [connected, setConnected] = useState(false);
  const panel = useRef(null);

  useEffect(() => {
    api.recentAlerts().then(setItems).catch(() => {});
    const token = getToken();
    const source = new EventSource(`${API_URL}/alerts/stream${token ? `?token=${encodeURIComponent(token)}` : ""}`);
    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false); // EventSource reconnects by itself
    source.addEventListener("usb", (e) => {
      const item = JSON.parse(e.data);
      setItems((prev) => [item, ...prev].slice(0, 50));
      if (item.alert && !item.imported) {
        setUnread((n) => n + 1);
        setToasts((t) => [...t, item]);
        setTimeout(() => setToasts((t) => t.filter((x) => x.event_id !== item.event_id)), 8000);
      }
    });
    return () => source.close();
  }, []);

  useEffect(() => {
    const close = (e) => panel.current && !panel.current.contains(e.target) && setOpen(false);
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);

  const go = (item) => {
    if (item.incident_id) onOpenIncident(item.incident_id);
    setOpen(false);
  };

  return (
    <span className="live-alerts" ref={panel}>
      <button
        className={`btn btn-sm bell ${unread ? "bell-unread" : ""}`}
        title={connected ? "Live feed connected" : "Live feed reconnecting…"}
        onClick={() => {
          setOpen((o) => !o);
          setUnread(0);
        }}
      >
        🔔{unread > 0 && <b className="bell-count">{unread}</b>}
      </button>
      {open && (
        <div className="alert-panel">
          <div className="alert-panel-head">
            Live feed <span className={`live ${connected ? "" : "live-off"}`}>{connected ? "connected" : "reconnecting"}</span>
          </div>
          {items.length === 0 && <div className="muted small">No events yet.</div>}
          {items.map((item) => (
            <button key={item.event_id} className={`alert-row alert-${item.risk_level}`} onClick={() => go(item)}>
              <span className={`badge badge-${item.risk_level}`}>
                {item.risk_level} <b>{Math.round(item.risk_score)}</b>
              </span>
              <span>
                <span className="mono">{item.device}</span> {{ connect: "→", disconnect: "left", typing: "typed on" }[item.event_type] || "→"} <span className="mono">{item.machine}</span>
                <span className="muted small">
                  {" "}
                  · {formatTime(item.timestamp)}
                  {item.imported && " · imported"}
                  {item.incident_id && ` · incident #${item.incident_id}`}
                </span>
              </span>
            </button>
          ))}
        </div>
      )}
      <div className="toasts" aria-live="polite">
        {toasts.map((t) => (
          <button key={t.event_id} className={`toast alert-${t.risk_level}`} onClick={() => go(t)}>
            <b>
              {t.risk_level.toUpperCase()} {Math.round(t.risk_score)}
            </b>{" "}
            {t.device} → {t.machine}
            {t.findings.length > 0 && <div className="small">{t.findings.join(", ")}</div>}
          </button>
        ))}
      </div>
    </span>
  );
}
