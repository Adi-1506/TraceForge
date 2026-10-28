"""Weighted risk scoring: every contributing factor is recorded as the explanation.

Rule weights come from server/scoring/standards.py (OWASP Risk Rating x evidence confidence);
each reasoning entry carries that derivation under "standard" so the dashboard and the report
can show where a number came from.

A device's risk is a property of the whole attachment, not of one event. Typing reports and the
disconnect arrive after the connect, so they carry forward the riskiest event of the same
attachment (its factors are copied, tagged with the event they came from) and add their own.
Without that, a clean typing report would replace a medium-risk connect as the device's
"latest" risk, and an injection found while typing would vanish again at unplug.
"""

from sqlalchemy.orm import Session

from server.detection.rules import Finding
from server.models import Event, RiskScore
from server.scoring import standards

BASE_SCORE = 5.0
# Score bands. They equal standards.SEVERITY_POINTS, so a single fully confident finding of
# OWASP severity S puts the event in level S on its own.
LEVELS = [(75, "critical"), (50, "high"), (25, "medium"), (0, "low")]


def level_for(score: float) -> str:
    return next(name for threshold, name in LEVELS if score >= threshold)


def _entry(f: Finding) -> dict:
    entry = {"factor": f.name, "source": f.source, "weight": f.weight, "explanation": f.explanation}
    rating = standards.assessment(f.name, f.detail)
    if rating is not None:
        entry["standard"] = rating
    return entry


def _baseline() -> dict:
    return {"factor": "baseline", "source": "system", "weight": BASE_SCORE, "explanation": "Baseline risk for any USB connection."}


def compute_score(findings: list[Finding]) -> tuple[float, list[dict]]:
    reasoning = [_baseline()] + [_entry(f) for f in findings]
    score = min(100.0, sum(r["weight"] for r in reasoning))
    return round(score, 1), reasoning


def _save(db: Session, event: Event, score: float, reasoning: list[dict]) -> RiskScore:
    rs = RiskScore(event_id=event.id, device_id=event.device_id, score=score, level=level_for(score), reasoning=reasoning)
    db.add(rs)
    return rs


def score_connect_event(db: Session, event: Event, findings: list[Finding]) -> RiskScore:
    score, reasoning = compute_score(findings)
    return _save(db, event, score, reasoning)


def attachment_peak(db: Session, event: Event) -> RiskScore | None:
    """The highest-scoring connect or typing event of the attachment this event belongs to:
    everything for this device on this machine since its most recent connect."""
    connect = (
        db.query(Event)
        .filter(
            Event.device_id == event.device_id,
            Event.machine_id == event.machine_id,
            Event.event_type == "connect",
            Event.id != event.id,
            Event.timestamp <= event.timestamp,
        )
        .order_by(Event.timestamp.desc(), Event.id.desc())
        .first()
    )
    if connect is None:
        return None
    return (
        db.query(RiskScore)
        .join(Event, Event.id == RiskScore.event_id)
        .filter(
            RiskScore.device_id == event.device_id,
            Event.machine_id == event.machine_id,
            Event.event_type.in_(("connect", "typing")),
            Event.id != event.id,
            Event.timestamp >= connect.timestamp,
            Event.timestamp <= event.timestamp,
        )
        .order_by(RiskScore.score.desc(), Event.timestamp.desc())
        .first()
    )


def score_followup_event(db: Session, event: Event, findings: list[Finding] | None = None) -> RiskScore:
    """A typing report or disconnect: the attachment's peak risk so far, plus anything found now."""
    peak = attachment_peak(db, event)
    if peak is None:
        reasoning = [_baseline()]
    else:
        reasoning = [{**r, "carried_from": r.get("carried_from", peak.event_id)} for r in peak.reasoning]
    reasoning += [_entry(f) for f in findings or []]
    score = round(min(100.0, sum(r["weight"] for r in reasoning)), 1)
    return _save(db, event, score, reasoning)


# Kept for callers that predate typing reports.
score_disconnect_event = score_followup_event
