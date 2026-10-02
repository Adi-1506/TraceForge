import { api, usePolling } from "../api.js";
import RiskBadge from "./RiskBadge.jsx";
import Timeline from "./Timeline.jsx";

function RiskBreakdown({ history }) {
  // Latest connection that carries its own reasoning (disconnects just inherit).
  const latest = history?.find((h) => h.reasoning[0]?.factor !== "inherited");
  if (!latest) return null;
  return (
    <div className="card-section">
      <h3>
        Risk score <RiskBadge level={latest.level} score={latest.score} />
      </h3>
      <ul className="factors">
        {latest.reasoning.map((r) => (
          <li key={r.factor}>
            <span className="factor-weight">+{r.weight}</span>
            <div>
              <div className="mono">{r.factor}</div>
              <div className="muted small">{r.explanation}</div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function DevicePanel({ deviceId }) {
  const device = usePolling(() => api.device(deviceId), deviceId);
  const timeline = usePolling(() => api.timeline(deviceId), deviceId);
  const risk = usePolling(() => api.riskHistory(deviceId), deviceId);
  const d = device.data;

  return (
    <div>
      {d && (
        <div className="card-section">
          <h2>{d.device_type || "Unknown device"}</h2>
          <div className="meta">
            <span className="mono">
              {d.vendor_id}:{d.product_id}
            </span>
            <span className="mono">serial {d.serial_number || "none"}</span>
            <span>{d.event_count} events</span>
            <span>seen on {d.machines.join(", ")}</span>
          </div>
        </div>
      )}
      <RiskBreakdown history={risk.data} />
      <div className="card-section">
        <h3>Timeline</h3>
        <Timeline entries={timeline.data} />
      </div>
    </div>
  );
}
