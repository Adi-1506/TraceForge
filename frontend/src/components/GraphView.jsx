import { useState } from "react";
import { api, usePolling } from "../api.js";
import AttackGraph from "./AttackGraph.jsx";

const WINDOWS = [
  [1, "Last day"],
  [7, "Last 7 days"],
  [30, "Last 30 days"],
];

// The fleet view: every device-machine connection in a window, which can be replayed in time order.
export default function GraphView() {
  const [days, setDays] = useState(7);
  const { data, error } = usePolling(() => api.graph({ days }), `graph-${days}`, 30000);
  return (
    <div className="card-section">
      <div className="graph-toolbar">
        <h3>Attack graph</h3>
        <span className="segmented">
          {WINDOWS.map(([d, label]) => (
            <button key={d} className={days === d ? "active" : ""} onClick={() => setDays(d)}>
              {label}
            </button>
          ))}
        </span>
      </div>
      <p className="muted small">
        Which devices touched which machines, counted back from the latest activity. Links are coloured by the worst risk
        seen on them; replay shows them in the order they happened.
      </p>
      {error && !data && <div className="empty">{error.message}</div>}
      {!data && !error && <div className="empty">Loading graph…</div>}
      {data && <AttackGraph data={data} />}
    </div>
  );
}
