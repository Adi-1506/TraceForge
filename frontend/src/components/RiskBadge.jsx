export default function RiskBadge({ level, score }) {
  if (!level) return <span className="badge badge-none">no data</span>;
  return (
    <span className={`badge badge-${level}`}>
      {level}
      {score != null && <b>{Math.round(score)}</b>}
    </span>
  );
}
