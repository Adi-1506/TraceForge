// NIST SP 800-30 Rev. 1 levels of risk (Table I-3), lowest first, and the colour tone each one uses.
export const RISK_LEVELS = ["very_low", "low", "moderate", "high", "very_high"];

const TONE = { very_low: "low", low: "low", moderate: "medium", high: "high", very_high: "critical" };

export const riskTone = (level) => TONE[level] || "none";
export const riskLabel = (level) => (level ? level.replace("_", " ") : level);
export const isHighRisk = (level) => level === "high" || level === "very_high";
