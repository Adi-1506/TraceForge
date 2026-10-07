"""Measure the behavioural model on held-out data instead of eyeballing the demo.

    python -m server.detection.evaluate [--devices 40] [--seed 1]

Simulates ten weeks of normal usage for many devices, each with its own habits
(usual hours, machines, enumeration time, interface order). The model trains on
weeks 1-7 only. Weeks 8-10 give held-out normal connections (false positive rate)
and, on random devices at random points, injected behavioural attacks of each type
(detection rate). No identity rule can see these attacks: the device's identity and
descriptor are unchanged, so this isolates what the ML layer adds.

Three detectors are compared on the same data:
  baseline-4   Isolation Forest on the original four features
  iforest-9    Isolation Forest on the current feature set
  iforest-9+   iforest-9 plus the out-of-training-range check (what the server runs)
"""

import argparse
import random
from datetime import datetime, timedelta, timezone

import numpy as np

from server.detection.features import FEATURE_NAMES, features_from_history
from server.detection.ml_model import _novelty, fit_bundle

BASELINE_4 = ["gap_log", "hour_of_day", "events_last_hour", "machines_seen"]
START = datetime(2026, 6, 1, tzinfo=timezone.utc)  # a Monday
TRAIN_DAYS, TOTAL_DAYS = 49, 70
ATTACKS_PER_TYPE = 40
INTERFACE_LAYOUTS = [[3], [8], [14, 14], [7], [2, 10], [1, 1, 3], [8, 3]]


def make_profiles(rng: random.Random, n: int) -> list[dict]:
    return [
        {
            "hour": rng.uniform(8.5, 17),
            "hour_sd": rng.uniform(0.5, 2.0),
            "p_day": rng.uniform(0.2, 0.95),
            "sessions": rng.choice([1, 1, 1, 2, 3]),
            "machines": list(range(rng.randint(1, 3))),
            "enum_ms": rng.uniform(30, 300),
            "order": rng.choice(INTERFACE_LAYOUTS),
        }
        for _ in range(n)
    ]


def normal_connect(rng: random.Random, p: dict, day: datetime) -> tuple:
    hour = min(max(rng.gauss(p["hour"], p["hour_sd"]), 0), 23.9)
    ts = day + timedelta(hours=hour)
    machine = p["machines"][0] if rng.random() < 0.8 else rng.choice(p["machines"])
    return (ts, machine, {"interface_order": p["order"], "duration_ms": p["enum_ms"] * rng.uniform(0.8, 1.25)})


def simulate(rng: random.Random, profiles: list[dict]) -> list[list[tuple]]:
    histories = []
    for p in profiles:
        events = []
        for d in range(TOTAL_DAYS):
            day = START + timedelta(days=d)
            if day.weekday() >= 5 or rng.random() > p["p_day"]:
                continue
            events += [normal_connect(rng, p, day) for _ in range(p["sessions"])]
        histories.append(sorted(events, key=lambda e: e[0]))
    return histories


def attack(kind: str, rng: random.Random, p: dict, prior: list[tuple]) -> list[tuple]:
    """Connect events for one attack, placed after the last normal event in `prior`."""
    day = (prior[-1][0] + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    base = normal_connect(rng, p, day)
    if kind == "burst":  # rapid re-plugging, e.g. retrying a payload
        return [(base[0] + timedelta(seconds=20 * i), base[1], base[2]) for i in range(6)]
    if kind == "off_hours":
        return [(day + timedelta(hours=rng.uniform(1, 4.5)), base[1], base[2])]
    if kind == "slow_enumeration":  # a programmable board emulating the device
        return [(base[0], base[1], {**base[2], "duration_ms": p["enum_ms"] * rng.uniform(8, 30)})]
    if kind == "order_change":
        order = p["order"][::-1] if len(set(p["order"])) > 1 else p["order"] + [3]
        return [(base[0], base[1], {**base[2], "interface_order": order})]
    if kind == "machine_hopping":  # the same device on several new machines within an hour
        return [(base[0] + timedelta(minutes=12 * i), 100 + i, base[2]) for i in range(4)]
    raise ValueError(kind)


ATTACK_TYPES = ["burst", "off_hours", "slow_enumeration", "order_change", "machine_hopping"]


def run(n_devices: int, seed: int) -> dict:
    rng = random.Random(seed)
    profiles = make_profiles(rng, n_devices)
    histories = simulate(rng, profiles)
    cutoff = START + timedelta(days=TRAIN_DAYS)

    train_rows, normal_rows = [], []
    for events in histories:
        for i, cur in enumerate(events):
            (train_rows if cur[0] < cutoff else normal_rows).append(features_from_history(events[:i], cur))

    attack_rows: dict[str, list[list[float]]] = {k: [] for k in ATTACK_TYPES}
    eligible = [i for i, h in enumerate(histories) if sum(e[0] >= cutoff for e in h) >= 2]
    for kind in ATTACK_TYPES:
        for _ in range(ATTACKS_PER_TYPE):
            d = rng.choice(eligible)
            held_out = [e for e in histories[d] if e[0] >= cutoff]
            point = rng.randrange(1, len(held_out))
            prior = [e for e in histories[d] if e[0] < held_out[point][0]]
            events = attack(kind, rng, profiles[d], prior)
            # An attack counts as detected if any of its connections is flagged.
            attack_rows[kind].append([features_from_history(prior + events[:j], e) for j, e in enumerate(events)])

    X_train = np.array(train_rows)
    idx4 = [FEATURE_NAMES.index(f) for f in BASELINE_4]
    b4, b9 = fit_bundle(X_train[:, idx4]), fit_bundle(X_train)

    def flags(rows: list[list[float]]) -> dict[str, bool]:
        X = np.array(rows)
        if4 = (b4["model"].decision_function(X[:, idx4]) < b4["threshold"]).any()
        if9 = (b9["model"].decision_function(X) < b9["threshold"]).any()
        novel = any(_novelty(b9, X[i : i + 1]) for i in range(len(X)))
        return {"baseline-4": bool(if4), "iforest-9": bool(if9), "iforest-9+": bool(if9 or novel)}

    detectors = ["baseline-4", "iforest-9", "iforest-9+"]
    normal_flags = [flags([r]) for r in normal_rows]
    result = {
        "training_rows": len(train_rows),
        "held_out_normal": len(normal_rows),
        "false_positive_rate": {d: sum(f[d] for f in normal_flags) / len(normal_flags) for d in detectors},
        "detection_rate": {},
    }
    all_attack_flags = []
    for kind, cases in attack_rows.items():
        fl = [flags(c) for c in cases]
        all_attack_flags += fl
        result["detection_rate"][kind] = {d: sum(f[d] for f in fl) / len(fl) for d in detectors}
    for d in detectors:
        tp = sum(f[d] for f in all_attack_flags)
        fp = sum(f[d] for f in normal_flags)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / len(all_attack_flags)
        result.setdefault("overall", {})[d] = {
            "precision": precision,
            "recall": recall,
            "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--devices", type=int, default=40)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()
    r = run(args.devices, args.seed)
    detectors = list(r["false_positive_rate"])

    print(f"training rows: {r['training_rows']}, held-out normal connections: {r['held_out_normal']}, "
          f"attacks: {ATTACKS_PER_TYPE} per type\n")
    print(f"{'':<22}" + "".join(f"{d:>13}" for d in detectors))
    for kind, rates in r["detection_rate"].items():
        print(f"{'detect ' + kind:<22}" + "".join(f"{rates[d]:>13.0%}" for d in detectors))
    print(f"{'false positive rate':<22}" + "".join(f"{r['false_positive_rate'][d]:>13.1%}" for d in detectors))
    for m in ("precision", "recall", "f1"):
        print(f"{m:<22}" + "".join(f"{r['overall'][d][m]:>13.2f}" for d in detectors))
    print("\nNumbers are on simulated data: they show what each detector can separate, not real-world accuracy.")


if __name__ == "__main__":
    main()
