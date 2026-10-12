import { useState } from "react";
import { DISPLAY_TZ, api, formatTime, usePolling } from "../api.js";

const KINDS = [
  ["auto", "Detect automatically"],
  ["setupapi", "Windows setupapi.dev.log"],
  ["linux", "Linux kernel log (journalctl -k / syslog)"],
  ["registry", "Windows registry export (.reg)"],
];

async function toBase64(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

// Import the USB history a seized machine already keeps, for machines that never ran the agent.
export default function EvidenceImport() {
  const [file, setFile] = useState(null);
  const [registry, setRegistry] = useState(null);
  const [kind, setKind] = useState("auto");
  const [machine, setMachine] = useState("");
  const [tz, setTz] = useState(DISPLAY_TZ);
  const [year, setYear] = useState(new Date().getFullYear());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const imports = usePolling(api.evidenceImports, "imports", 15000);

  const submit = async (dryRun) => {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const out = await api.importEvidence({
        filename: file.name,
        content_b64: await toBase64(file),
        registry_b64: registry ? await toBase64(registry) : null,
        kind,
        machine_hostname: machine.trim() || null,
        timezone: tz,
        year: Number(year),
        dry_run: dryRun,
      });
      setResult({ ...out, dryRun });
      if (!dryRun) imports.refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <div className="card-section">
        <h3>Import evidence from a seized machine</h3>
        <p className="muted small">
          Investigate a computer that never ran the agent, from the USB history its operating system already keeps. Imported
          events go through the same rules, behavioural model, trust and incidents as live ones, join the evidence hash chain,
          and each file is recorded with its SHA-256.
        </p>
        <ul className="muted small evidence-sources">
          <li>
            <b>Windows:</b> <span className="mono">C:\Windows\INF\setupapi.dev.log</span> (first install of every device),
            optionally with <span className="mono">reg export HKLM\SYSTEM\CurrentControlSet\Enum\USB usb.reg</span>
          </li>
          <li>
            <b>Linux:</b> <span className="mono">journalctl -k -o short-iso &gt; kern.log</span>, or{" "}
            <span className="mono">/var/log/syslog</span> / <span className="mono">kern.log</span>
          </li>
        </ul>
        <div className="evidence-form">
          <label>
            Evidence file
            <input type="file" onChange={(e) => { setFile(e.target.files[0] || null); setResult(null); }} />
          </label>
          <label>
            Registry export (optional, fills in device types)
            <input type="file" accept=".reg" onChange={(e) => setRegistry(e.target.files[0] || null)} />
          </label>
          <label>
            Type
            <select className="search-input" value={kind} onChange={(e) => setKind(e.target.value)}>
              {KINDS.map(([v, l]) => (
                <option key={v} value={v}>
                  {l}
                </option>
              ))}
            </select>
          </label>
          <label>
            Machine hostname (Windows files do not name it)
            <input className="search-input" value={machine} placeholder="e.g. SEIZED-LAPTOP" onChange={(e) => setMachine(e.target.value)} />
          </label>
          <label>
            Machine's time zone
            <input className="search-input" value={tz} onChange={(e) => setTz(e.target.value)} />
          </label>
          <label>
            Year (syslog lines carry none)
            <input className="search-input" type="number" value={year} onChange={(e) => setYear(e.target.value)} />
          </label>
        </div>
        <div className="row">
          <button className="btn" disabled={!file || busy} onClick={() => submit(true)}>
            Preview
          </button>
          <button className="btn" disabled={!file || busy} onClick={() => submit(false)}>
            {busy ? "Working…" : "Import"}
          </button>
          {error && <span className="error small">{error}</span>}
        </div>
      </div>

      {result && (
        <div className="card-section">
          <h3>{result.dryRun ? "Preview" : "Imported"}</h3>
          <div className="meta">
            <span>{result.kind}</span>
            <span>{result.events_found} event(s) found</span>
            {!result.dryRun && <span>{result.events_imported} imported</span>}
            {!result.dryRun && <span>{result.new_devices} new device(s)</span>}
            {!result.dryRun && result.duplicates_skipped > 0 && <span>{result.duplicates_skipped} already recorded by the agent</span>}
            {!result.dryRun && result.incidents.length > 0 && <span className="chip chip-tampered">incidents {result.incidents.map((i) => `#${i}`).join(", ")}</span>}
          </div>
          <div className="muted small mono export-hash-left">SHA-256 {result.sha256}</div>
          {result.warnings.map((w) => (
            <div key={w} className="error small">
              {w}
            </div>
          ))}
          {result.dryRun && result.preview.length > 0 && (
            <div className="table-scroll">
              <table className="table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Event</th>
                    <th>Machine</th>
                    <th>Device</th>
                    <th>Serial</th>
                    <th>Type</th>
                  </tr>
                </thead>
                <tbody>
                  {result.preview.map((p, i) => (
                    <tr key={i}>
                      <td className="muted">{formatTime(p.timestamp)}</td>
                      <td>{p.event_type}</td>
                      <td className="mono">{p.machine_hostname}</td>
                      <td className="mono">
                        {p.vendor_id}:{p.product_id}
                      </td>
                      <td className="mono">{p.serial_number || "none"}</td>
                      <td>{p.device_type}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {result.undated_devices.length > 0 && (
            <p className="muted small">
              {result.undated_devices.length} device(s) known to the machine with no recorded time (registry):{" "}
              {result.undated_devices.map((d) => `${d.vendor_id}:${d.product_id}${d.device_type ? ` ${d.device_type}` : ""}`).join(", ")}
            </p>
          )}
        </div>
      )}

      <div className="card-section">
        <h3>Imported evidence files</h3>
        {!imports.data?.length ? (
          <div className="muted small">Nothing imported yet.</div>
        ) : (
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th>When</th>
                  <th>File</th>
                  <th>Type</th>
                  <th>Machine</th>
                  <th>Events</th>
                  <th>By</th>
                  <th>SHA-256</th>
                </tr>
              </thead>
              <tbody>
                {imports.data.map((r) => (
                  <tr key={r.id}>
                    <td className="muted">{formatTime(r.imported_at)}</td>
                    <td className="mono">{r.filename}</td>
                    <td>{r.kind}</td>
                    <td className="mono">{r.machine_hostname || "from log"}</td>
                    <td>{r.events_imported}</td>
                    <td className="mono">{r.imported_by}</td>
                    <td className="mono small" title={r.sha256}>
                      {r.sha256.slice(0, 16)}…
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
