"""Admin commands.

    python -m server.manage create-user <username> --role admin      (prompts for the password)
    python -m server.manage hash-key                                  (prints API_KEY_HASH for a key)
"""

import argparse
import getpass
import hashlib
import secrets

from server import audit
from server.auth import ROLES, create_user
from server.database import Base, SessionLocal, engine


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m server.manage")
    sub = parser.add_subparsers(dest="command", required=True)
    cu = sub.add_parser("create-user", help="add an investigator or admin account")
    cu.add_argument("username")
    cu.add_argument("--role", choices=ROLES, default="investigator")
    sub.add_parser("hash-key", help="generate (or hash) an agent API key for API_KEY_HASH")
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
    else:
        key = getpass.getpass("API key to hash (leave empty to generate one): ") or secrets.token_urlsafe(32)
        print(f"Give agents:      TRACEFORGE_API_KEY={key}")
        print(f"Put in .env:      API_KEY_HASH={hashlib.sha256(key.encode()).hexdigest()}")
        print("Then remove API_KEY from .env so only the hash is stored on the server.")


if __name__ == "__main__":
    main()
