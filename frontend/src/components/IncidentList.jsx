import { api, formatTime, usePolling } from "../api.js";
import RiskBadge from "./RiskBadge.jsx";
import Timeline from "./Timeline.jsx";

export function IncidentTable({ incidents, selectedId, onSelect }) {
  if (!incidents) return <div className="empty">Loading incidents…</div>;
  if (incidents.length === 0) return <div className="empty">No incidents. Suspicious events will be grouped here.</div>;
  return (
    <div className="incident-list">
      {incidents.map((i) => (
        <button key={i.id} className={`incident ${i.id === selectedId ? "selected" : ""}`} onClick={() => onSelect(i.id)}>
          <div className="incident-head">
            <b>Incident #{i.id}</b>
            <RiskBadge level={i.level} score={i.max_score} />
          </div>
          <div>{i.device_label}</div>
          <div className="muted small">
            on <span className="mono">{i.machine_hostname}</span> · {i.event_count} events · {formatTime(i.start_time)}
          </div>
        </button>
      ))}
    </div>
  );
}

export function IncidentPanel({ incidentId, onOpenDevice }) {
  const { data } = usePolling(() => api.incident(incidentId), incidentId);
  if (!data) return <div className="empty">Loading incident…</div>;
  return (
    <div>
      <div className="card-section">
        <h2>Incident #{data.id}</h2>
        <div className="meta">
          <span>{data.device_label}</span>
          <span>
            on <span className="mono">{data.machine_hostname}</span>
          </span>
          <span>
            {formatTime(data.start_time)} → {formatTime(data.end_time)}
          </span>
        </div>
        <button className="link" onClick={() => onOpenDevice(data.device_id)}>
          Open device profile →
        </button>
      </div>
      <div className="card-section">
        <h3>Correlated events</h3>
        <Timeline entries={data.timeline} />
      </div>
    </div>
  );
}
