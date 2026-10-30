"""Risk assessment scales from NIST SP 800-30 Rev. 1, Guide for Conducting Risk Assessments
(https://doi.org/10.6028/NIST.SP.800-30r1), with ISO/IEC 27005's risk = likelihood x consequence.

- Likelihood and impact are given as semi-quantitative values from 0 to 100 and read on the
  five-level scales of Tables G-2 to G-4 (likelihood) and H-3 (impact):
      Very High 96-100, High 80-95, Moderate 21-79, Low 5-20, Very Low 0-4.
- The level of risk is Table I-2, the NIST matrix combining the likelihood and impact levels.
- The risk value is likelihood x impact / 100 (ISO/IEC 27005), kept inside the Table I-3 range of
  the level Table I-2 gives, so the number and the level always agree and numbers can be added up
  and ranked on the same Table I-3 scale.
"""

LEVELS = ("very_low", "low", "moderate", "high", "very_high")
LABELS = {"very_low": "Very Low", "low": "Low", "moderate": "Moderate", "high": "High", "very_high": "Very High"}

# Tables G-2, G-3, G-4, H-3 and I-3 share one semi-quantitative scale.
SCALE = {"very_low": (0, 4), "low": (5, 20), "moderate": (21, 79), "high": (80, 95), "very_high": (96, 100)}

# Table I-2: level of risk, by likelihood (rows) and level of impact (columns, Very Low to Very High).
RISK_MATRIX = {
    "very_high": ("very_low", "low", "moderate", "high", "very_high"),
    "high": ("very_low", "low", "moderate", "high", "very_high"),
    "moderate": ("very_low", "low", "moderate", "moderate", "high"),
    "low": ("very_low", "low", "low", "low", "moderate"),
    "very_low": ("very_low", "very_low", "very_low", "low", "low"),
}

# The Sigma rule level that corresponds to each NIST level (Sigma has five levels too).
SIGMA_LEVEL = {"very_low": "informational", "low": "low", "moderate": "medium", "high": "high", "very_high": "critical"}


def level_for(value: float) -> str:
    """The NIST level a 0-100 semi-quantitative value falls in."""
    return next(name for name in reversed(LEVELS) if value >= SCALE[name][0])


def rank(level: str) -> int:
    return LEVELS.index(level)


def risk_level(likelihood: float, impact: float) -> str:
    """Table I-2."""
    return RISK_MATRIX[level_for(likelihood)][rank(level_for(impact))]


def risk_value(likelihood: float, impact: float) -> float:
    """likelihood x impact / 100, kept within the Table I-3 range of the Table I-2 level."""
    lo, hi = SCALE[risk_level(likelihood, impact)]
    return round(min(max(likelihood * impact / 100, lo), hi), 1)
