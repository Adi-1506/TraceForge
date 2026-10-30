import { riskLabel, riskTone } from "../risk.js";

export default function RiskBadge({ level, score }) {
  if (!level) return <span className="badge badge-none">no data</span>;
  return (
    <span className={`badge badge-${riskTone(level)}`} title="NIST SP 800-30 level of risk">
      {riskLabel(level)}
      {score != null && <b>{Math.round(score)}</b>}
    </span>
  );
}
