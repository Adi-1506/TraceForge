import { api, formatTime, usePolling } from "../api.js";

const LABELS = {
  "auth.login": "Signed in",
  "auth.login_failed": "Failed sign-in",
  "auth.logout": "Signed out",
  "incident.update": "Changed incident",
  "device.trust": "Changed device trust",
  "ml.train": "Retrained model",
  "user.create": "Created user",
};

function describe(e) {
  const d = e.detail || {};
  if (e.action === "incident.update") {
    const parts = [];
    if (d.status) parts.push(`${d.previous_status} → ${d.status}`);
    if (d.note !== undefined) parts.push(`note: "${d.note}"`);
    return parts.join(", ");
  }
  if (e.action === "device.trust") return `${d.previous} → ${d.status}${d.note ? ` (${d.note})` : ""}`;
  if (e.action === "ml.train") return `${d.algorithm}, ${d.rows} connections, ${d.excluded} left out`;
  if (e.action === "user.create") return `${d.username} (${d.role})`;
  return "";
}

export default function AuditLog() {
  const { data, error } = usePolling(api.audit, "audit", 5000);
  if (error && !data) return <div className="empty">{error.message}</div>;
  if (!data) return <div className="empty">Loading audit log…</div>;
  if (data.length === 0) return <div className="empty">No actions recorded yet.</div>;
  return (
    <div className="table-scroll">
      <table className="table">
        <thead>
          <tr>
            <th>When</th>
            <th>Who</th>
            <th>Action</th>
            <th>Target</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {data.map((e) => (
            <tr key={e.id} className={e.action === "auth.login_failed" ? "audit-warn" : ""}>
              <td className="muted">{formatTime(e.timestamp)}</td>
              <td className="mono">{e.actor}</td>
              <td>{LABELS[e.action] || e.action}</td>
              <td className="mono">{e.target_type ? `${e.target_type} #${e.target_id}` : "–"}</td>
              <td className="small">{describe(e)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
