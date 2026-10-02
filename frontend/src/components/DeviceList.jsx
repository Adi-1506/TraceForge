import { formatTime } from "../api.js";
import RiskBadge from "./RiskBadge.jsx";

export default function DeviceList({ devices, selectedId, onSelect }) {
  if (!devices) return <div className="empty">Loading devices…</div>;
  if (devices.length === 0)
    return <div className="empty">No devices yet. Run the agent or seed the synthetic dataset.</div>;

  return (
    <table className="table">
      <thead>
        <tr>
          <th>Device</th>
          <th>Status</th>
          <th>Machines</th>
          <th>Last seen</th>
          <th>Risk</th>
        </tr>
      </thead>
      <tbody>
        {devices.map((d) => (
          <tr key={d.id} className={d.id === selectedId ? "selected" : ""} onClick={() => onSelect(d.id)}>
            <td>
              <div className="device-name">{d.device_type || "Unknown type"}</div>
              <div className="mono muted">
                {d.vendor_id}:{d.product_id} · {d.serial_number || "no serial"}
              </div>
            </td>
            <td>
              <span className={`chip ${d.known ? "chip-known" : "chip-unknown"}`}>{d.known ? "known" : "unknown"}</span>
            </td>
            <td>{d.machine_count}</td>
            <td className="muted">{d.last_seen ? formatTime(d.last_seen) : "–"}</td>
            <td>
              <RiskBadge level={d.risk_level} score={d.risk_score} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
