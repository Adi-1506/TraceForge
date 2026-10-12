"""Import USB evidence from a seized machine through the same pipeline as live agent events.

Imported events get the rules, behavioural model, trust, incidents and the evidence hash chain like
any other. Each file is recorded with its SHA-256 (chain of custody) and cannot be imported twice;
events the live agent already reported (same device, machine and type within a few seconds) are skipped.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy.orm import Session

from server.forensics import parsers
from server.models import Device, Event, EvidenceImport, Machine
from server.schemas import EventIngest
from server.services.ingest import process_event
from server.timeutil import as_utc

KINDS = ("setupapi", "registry", "linux")
DUPLICATE_WINDOW = timedelta(seconds=5)


class ImportRejected(ValueError):
    pass


@dataclass
class ImportOutcome:
    kind: str
    sha256: str
    events_found: int
    events_imported: int = 0
    duplicates_skipped: int = 0
    new_devices: int = 0
    incidents: list[int] = field(default_factory=list)
    undated_devices: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    import_id: int | None = None
    preview: list[dict] = field(default_factory=list)


def parse(raw: bytes, kind: str, tz: str, year: int, registry_raw: bytes | None = None) -> parsers.ParseResult:
    text = parsers.decode(raw)
    kind = kind if kind != "auto" else parsers.detect_kind(text)
    if kind not in KINDS:
        raise ImportRejected("Could not tell what kind of file this is; choose setupapi, registry or linux.")
    if kind == "setupapi":
        result = parsers.parse_setupapi(text, tz)
    elif kind == "linux":
        result = parsers.parse_linux(text, tz, year)
    else:
        result = parsers.parse_registry(text)
    if registry_raw is not None and kind != "registry":
        parsers.enrich_from_registry(result.events, parsers.parse_registry(parsers.decode(registry_raw)))
    return result


def _already_recorded(db: Session, e: parsers.ParsedEvent, hostname: str) -> bool:
    ts = e.timestamp
    return (
        db.query(Event.id)
        .join(Device, Device.id == Event.device_id)
        .join(Machine, Machine.id == Event.machine_id)
        .filter(
            Machine.hostname == hostname,
            Device.vendor_id == e.vendor_id,
            Device.product_id == e.product_id,
            Device.serial_number == e.serial_number if e.serial_number is not None else Device.serial_number.is_(None),
            Event.event_type == e.event_type,
            Event.timestamp >= ts - DUPLICATE_WINDOW,
            Event.timestamp <= ts + DUPLICATE_WINDOW,
        )
        .first()
        is not None
    )


def run(
    db: Session,
    raw: bytes,
    filename: str,
    machine_hostname: str | None,
    kind: str = "auto",
    tz: str = "UTC",
    year: int = 2026,
    dry_run: bool = False,
    imported_by: str = "anonymous",
    registry_raw: bytes | None = None,
) -> ImportOutcome:
    digest = hashlib.sha256(raw).hexdigest()
    if not dry_run and db.query(EvidenceImport).filter(EvidenceImport.sha256 == digest).first():
        raise ImportRejected("This exact file was already imported (same SHA-256).")
    result = parse(raw, kind, tz, year, registry_raw)
    outcome = ImportOutcome(result.kind, digest, len(result.events), undated_devices=result.undated, warnings=result.warnings)

    needs_host = any(e.machine_hostname is None for e in result.events)
    if needs_host and not machine_hostname:
        raise ImportRejected("This file does not name its machine; give the machine's hostname.")

    if dry_run:
        outcome.preview = [
            {
                "timestamp": as_utc(e.timestamp).isoformat(),
                "event_type": e.event_type,
                "machine_hostname": machine_hostname or e.machine_hostname,
                "vendor_id": e.vendor_id,
                "product_id": e.product_id,
                "serial_number": e.serial_number,
                "device_type": e.device_type,
            }
            for e in result.events[:200]
        ]
        return outcome

    record = EvidenceImport(filename=filename, sha256=digest, kind=result.kind, machine_hostname=machine_hostname, imported_by=imported_by)
    db.add(record)
    db.flush()
    incidents: set[int] = set()
    for e in result.events:
        host = machine_hostname or e.machine_hostname
        if _already_recorded(db, e, host):
            outcome.duplicates_skipped += 1
            continue
        out = process_event(
            db,
            EventIngest(
                machine_hostname=host,
                vendor_id=e.vendor_id,
                product_id=e.product_id,
                serial_number=e.serial_number,
                device_type=e.device_type,
                event_type=e.event_type,
                timestamp=e.timestamp,
                source=f"import:{result.kind}",
                evidence={"file": filename, "sha256": digest, "import_id": record.id, **e.detail},
            ),
        )
        outcome.events_imported += 1
        outcome.new_devices += int(out.is_new_device)
        if out.incident is not None:
            incidents.add(out.incident.id)
    record.events_imported = outcome.events_imported
    db.commit()
    outcome.incidents = sorted(incidents)
    outcome.import_id = record.id
    return outcome
