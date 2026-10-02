const CARDS = [
  ["devices", "Devices"],
  ["machines", "Machines"],
  ["events", "USB events"],
  ["anomalies", "Anomalies"],
  ["open_incidents", "Open incidents", "warn"],
  ["high_risk_devices", "High-risk devices", "danger"],
];

export default function StatCards({ stats }) {
  return (
    <div className="stats">
      {CARDS.map(([key, label, tone]) => (
        <div key={key} className={`stat ${tone && stats?.[key] > 0 ? `stat-${tone}` : ""}`}>
          <div className="stat-value">{stats ? stats[key] : "–"}</div>
          <div className="stat-label">{label}</div>
        </div>
      ))}
    </div>
  );
}
