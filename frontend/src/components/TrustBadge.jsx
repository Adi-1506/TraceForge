const TONE = { trusted: "low", suspicious: "medium", untrusted: "high", blocklisted: "critical" };

export default function TrustBadge({ level, score, status }) {
  if (!level) return <span className="badge badge-none">no data</span>;
  return (
    <span className={`badge badge-${TONE[level] || "none"}`} title={status && status !== "auto" ? `Set by an investigator (${status})` : "Computed from history"}>
      {level}
      {level !== "blocklisted" && score != null && <b>{Math.round(score)}</b>}
      {status && status !== "auto" && <span aria-label="investigator override">✎</span>}
    </span>
  );
}
