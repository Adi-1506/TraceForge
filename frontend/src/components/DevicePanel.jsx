import { useState } from "react";
import { api, usePolling } from "../api.js";
import RiskBadge from "./RiskBadge.jsx";
import Timeline from "./Timeline.jsx";
import TrustBadge from "./TrustBadge.jsx";

const OVERRIDES = [
  ["auto", "Auto"],
  ["trusted", "Trusted"],
  ["blocklisted", "Blocklisted"],
];

function TrustSection({ device, onChanged }) {
  const [note, setNote] = useState(device.trust_note || "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  const save = async (status) => {
    setSaving(true);
    setError(null);
    try {
      await api.setTrust(device.id, status, note);
      onChanged();
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="card-section">
      <h3>
        Device trust <TrustBadge level={device.trust_level} score={device.trust_score} status={device.trust_status} />
      </h3>
      <ul className="factors">
        {device.trust_factors.map((f) => (
          <li key={f.factor}>
            <span className={`factor-weight ${f.weight < 0 ? "factor-negative" : ""}`}>
              {f.weight > 0 ? `+${f.weight}` : f.weight}
            </span>
            <div>
              <div className="mono">{f.factor}</div>
              <div className="muted small">{f.explanation}</div>
            </div>
          </li>
        ))}
      </ul>
      <p className="muted small">
        Trusted silences the "new machine" alert for a device that moves between machines; clone, descriptor and
        behaviour checks still apply. Blocklisted flags every future connection. Nothing is blocked on the machine.
      </p>
      <input
        className="search-input trust-note"
        placeholder="Reason (optional), e.g. reported stolen"
        value={note}
        maxLength={500}
        onChange={(e) => setNote(e.target.value)}
      />
      <div className="segmented">
        {OVERRIDES.map(([value, label]) => (
          <button key={value} disabled={saving} className={device.trust_status === value ? "active" : ""} onClick={() => save(value)}>
            {label}
          </button>
        ))}
      </div>
      {error && <div className="error small">{error}</div>}
    </div>
  );
}

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

function DescriptorSection({ descriptor }) {
  if (!descriptor) return null;
  const interfaces = descriptor.interfaces || [];
  return (
    <div className="card-section">
      <h3>USB descriptor profile</h3>
      <div className="meta">
        {descriptor.fingerprint ? (
          <span>
            fingerprint <span className="mono">{descriptor.fingerprint}</span>
          </span>
        ) : (
          <span className="muted">no structural fingerprint (agent could not read the descriptor tree)</span>
        )}
        {descriptor.bcd_usb && <span className="mono">USB {descriptor.bcd_usb}</span>}
        {descriptor.pnp_class && <span className="mono">{descriptor.pnp_class}</span>}
        {descriptor.service && <span className="mono">{descriptor.service}</span>}
      </div>
      {interfaces.length > 0 && (
        <ul className="factors">
          {interfaces.map((i, n) => (
            <li key={n}>
              <span className="factor-weight mono">#{i.interface_number ?? n}</span>
              <div>
                <div className="mono">
                  class 0x{Number(i.interface_class).toString(16).padStart(2, "0")} / sub {i.interface_subclass} / proto{" "}
                  {i.interface_protocol}
                </div>
                <div className="muted small mono">
                  {(i.endpoints || []).map((e) => `${e.direction} ${e.transfer_type} ${e.max_packet_size}B`).join(" · ") ||
                    "no endpoints"}
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
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
          <div className="device-header-row">
            <div>
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
            <div className="export-actions">
              <a
                href={api.exportDeviceUrl(deviceId, "json")}
                target="_blank"
                rel="noreferrer"
                download={`forensic_report_${d.vendor_id}_${d.product_id}.json`}
                className="btn btn-sm"
                title="Download complete forensic JSON dossier"
              >
                Export JSON
              </a>
              <a
                href={api.exportDeviceUrl(deviceId, "csv")}
                target="_blank"
                rel="noreferrer"
                download={`timeline_${d.vendor_id}_${d.product_id}.csv`}
                className="btn btn-sm"
                title="Download event timeline CSV"
              >
                Export CSV
              </a>
            </div>
          </div>
        </div>
      )}
      {d && <TrustSection key={d.id} device={d} onChanged={device.refresh} />}
      <RiskBreakdown history={risk.data} />
      <DescriptorSection descriptor={d?.descriptor_json} />
      <div className="card-section">
        <h3>Timeline</h3>
        <Timeline entries={timeline.data} />
      </div>
    </div>
  );
}
