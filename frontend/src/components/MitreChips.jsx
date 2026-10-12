// MITRE ATT&CK techniques behind a finding or incident, each linking to its page on attack.mitre.org.
export default function MitreChips({ techniques, showNames = false }) {
  if (!techniques?.length) return null;
  return (
    <span className="mitre-chips">
      {techniques.map((t) => (
        <a
          key={t.id}
          className="chip chip-mitre"
          href={t.url}
          target="_blank"
          rel="noreferrer"
          title={`${t.id} ${t.name} (${t.tactic})`}
          onClick={(e) => e.stopPropagation()}
        >
          {t.id}
          {showNames && ` ${t.name}`}
        </a>
      ))}
    </span>
  );
}
