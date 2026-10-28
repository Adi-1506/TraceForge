"""Admin commands.

    python -m server.manage create-user <username> --role admin      (prompts for the password)
    python -m server.manage hash-key                                  (prints API_KEY_HASH for a key)
    python -m server.manage agent-key LAB-PC-01                       (a key that may only report for that machine)
    python -m server.manage import setupapi.dev.log --machine SEIZED-PC [--registry usb.reg] [--dry-run]
"""

import argparse
import getpass
import hashlib
import secrets

from server import audit
from server.auth import ROLES, create_user
from server.database import Base, SessionLocal, engine


def run_import(args) -> None:
    from pathlib import Path

    from server.config import settings
    from server.database import upgrade_schema
    from server.forensics import importer

    Base.metadata.create_all(bind=engine)
    upgrade_schema()
    path = Path(args.file)
    with SessionLocal() as db:
        try:
            out = importer.run(
                db,
                path.read_bytes(),
                path.name,
                args.machine,
                kind=args.kind,
                tz=args.timezone or settings.timezone,
                year=args.year,
                dry_run=args.dry_run,
                imported_by="cli",
                registry_raw=Path(args.registry).read_bytes() if args.registry else None,
            )
        except importer.ImportRejected as exc:
            raise SystemExit(str(exc))
        if not args.dry_run:
            audit.record(db, "cli", "evidence.import", "evidence_import", out.import_id, filename=path.name, sha256=out.sha256, kind=out.kind, events=out.events_imported)
            db.commit()
    print(f"{path.name}: {out.kind}, SHA-256 {out.sha256}")
    for row in out.preview:
        print(f"  {row['timestamp']}  {row['event_type']:<10} {row['vendor_id']}:{row['product_id']}  {row['serial_number'] or '(no serial)'}  {row['device_type']}")
    if not args.dry_run:
        print(f"Imported {out.events_imported} event(s), {out.new_devices} new device(s), skipped {out.duplicates_skipped} already recorded.")
        if out.incidents:
            print(f"Incidents opened or extended: {', '.join(f'#{i}' for i in out.incidents)}")
    if out.undated_devices:
        print(f"{len(out.undated_devices)} device(s) known to the machine with no recorded time (registry).")
    for w in out.warnings:
        print(f"warning: {w}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m server.manage")
    sub = parser.add_subparsers(dest="command", required=True)
    cu = sub.add_parser("create-user", help="add an investigator or admin account")
    cu.add_argument("username")
    cu.add_argument("--role", choices=ROLES, default="investigator")
    sub.add_parser("hash-key", help="generate (or hash) an agent API key for API_KEY_HASH")
    ak = sub.add_parser("agent-key", help="generate a key bound to one machine, for AGENT_KEYS")
    ak.add_argument("hostname")
    im = sub.add_parser("import", help="import USB evidence from a seized machine")
    im.add_argument("file", help="setupapi.dev.log, a .reg export of the USB Enum key, or a Linux kernel log")
    im.add_argument("--machine", help="the seized machine's hostname (Linux logs name it themselves)")
    im.add_argument("--kind", default="auto", choices=("auto", "setupapi", "registry", "linux"))
    im.add_argument("--timezone", default=None, help="the seized machine's time zone (default: TIMEZONE)")
    im.add_argument("--year", type=int, default=2026, help="year for syslog lines, which carry none")
    im.add_argument("--registry", help="optional .reg export to fill in device types")
    im.add_argument("--dry-run", action="store_true", help="parse and list what would be imported")
    args = parser.parse_args()

    if args.command == "create-user":
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Repeat password: "):
            raise SystemExit("Passwords do not match.")
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            try:
                user = create_user(db, args.username, password, args.role)
            except ValueError as exc:
                raise SystemExit(str(exc))
            audit.record(db, "cli", "user.create", "user", user.id, username=user.username, role=user.role)
            db.commit()
        print(f"Created {args.role} '{args.username}'.")
    elif args.command == "import":
        run_import(args)
    elif args.command == "agent-key":
        key = secrets.token_urlsafe(32)
        print(f"On {args.hostname}:   TRACEFORGE_API_KEY={key}")
        print(f"Add to AGENT_KEYS:  {args.hostname}={hashlib.sha256(key.encode()).hexdigest()}")
        print("Entries are comma-separated. Set REQUIRE_AGENT_KEYS=true once every agent has its own key.")
    else:
        key = getpass.getpass("API key to hash (leave empty to generate one): ") or secrets.token_urlsafe(32)
        print(f"Give agents:      TRACEFORGE_API_KEY={key}")
        print(f"Put in .env:      API_KEY_HASH={hashlib.sha256(key.encode()).hexdigest()}")
        print("Then remove API_KEY from .env so only the hash is stored on the server.")


if __name__ == "__main__":
    main()
