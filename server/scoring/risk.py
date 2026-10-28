"""Risk scoring under NIST SP 800-30 Rev. 1 and ISO/IEC 27005, with every factor recorded as the explanation.

- Each finding carries a risk value from its likelihood and impact (server/scoring/nist.py): rule
  findings take them from their Sigma rule, ML findings from the model.
- An event's risk is its findings' values added up, capped at 100: NIST SP 800-30 risk
  aggregation, where several moderate risks together can make a higher one (Chapter 2, p. 13).
- Its level is the Table I-3 level of that value: Very Low 0-4, Low 5-20, Moderate 21-79,
  High 80-95, Very High 96-100. A finding's value already lies in its own Table I-2 level, so an
  event is never rated below its worst finding.
"""

from sqlalchemy.orm import Session

from server.detection.rules import Finding
from server.models import Event, RiskScore
from server.scoring import nist

NO_FINDINGS = {"factor": "no_findings", "source": "system", "weight": 0.0, "explanation": "No Sigma rule or model finding matched this event."}


def level_for(score: float) -> str:
    return nist.level_for(score)


def _factor(f: Finding) -> dict:
    return {"factor": f.name, "source": f.source, "weight": f.weight, "explanation": f.explanation}


def compute_score(findings: list[Finding]) -> tuple[float, list[dict]]:
    reasoning = [_factor(f) for f in findings] or [dict(NO_FINDINGS)]
    score = min(100.0, sum(r["weight"] for r in reasoning))
    return round(score, 1), reasoning


def score_connect_event(db: Session, event: Event, findings: list[Finding]) -> RiskScore:
    score, reasoning = compute_score(findings)
    rs = RiskScore(event_id=event.id, device_id=event.device_id, score=score, level=level_for(score), reasoning=reasoning)
    db.add(rs)
    return rs


def score_disconnect_event(db: Session, event: Event, findings: list[Finding] | None = None) -> RiskScore:
    """A disconnect carries the risk of the connection it closes, plus anything found at unplug (a large copy)."""
    last = (
        db.query(RiskScore)
        .join(Event, Event.id == RiskScore.event_id)
        .filter(RiskScore.device_id == event.device_id, Event.event_type == "connect", Event.id != event.id)
        .order_by(Event.timestamp.desc())
        .first()
    )
    if last is None:
        score, reasoning = compute_score([])
    else:
        score = last.score
        reasoning = [{"factor": "inherited", "source": "system", "weight": last.score, "explanation": f"Inherits the risk of the preceding connection (event {last.event_id})."}]
    for f in findings or []:
        reasoning.append(_factor(f))
    if findings:
        reasoning = [r for r in reasoning if r["factor"] != "no_findings"]
        score = round(min(100.0, (last.score if last else 0.0) + sum(f.weight for f in findings)), 1)
    rs = RiskScore(event_id=event.id, device_id=event.device_id, score=score, level=level_for(score), reasoning=reasoning)
    db.add(rs)
    return rs
