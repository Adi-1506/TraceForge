"""Check the evidence-confidence priors in standards.py against labelled data.

    python -m server.scoring.calibrate [--seeds 1 2 3 4 5] [--trials 8]

Each rule weight is c x OWASP severity points, where c ("how sure are we this finding means the
attack?") is an analyst prior. This replays the labelled synthetic scenarios from server/evaluate.py
and measures, for every finding, its empirical precision:

    precision = P(event is part of an attack trial | finding fired)

with a Laplace estimate (hits + 1) / (fires + 2), so a finding that fired twice is not reported
as 100% certain. It also fits an L2-regularised logistic regression over the finding indicators;
its coefficients are the log-odds each finding adds once the others are accounted for.

Caveat, as for evaluate.py: the data is synthetic, so a precision here says how the indicator
behaves on scenarios we generated, not in a real organisation. A large gap between the prior and
the measurement is a prompt to look at the rule or the scenario, not an automatic correction.
"""

import argparse
from collections import Counter

import numpy as np
from sklearn.linear_model import LogisticRegression

from server.evaluate import BENIGN_KINDS, simulation
from server.models import Anomaly
from server.scoring import standards


def observations(seeds: list[int], n_trials: int) -> list[tuple[set[str], int]]:
    """(finding names on the event, 1 if the event belongs to an attack trial else 0)."""
    rows = []
    for seed in seeds:
        with simulation(seed, n_trials) as sim:
            labelled = [(i, 0) for i in sim.normal]
            labelled += [(i, 0 if kind in BENIGN_KINDS else 1) for kind, ids in sim.trials for i in ids]
            for event_id, label in labelled:
                names = {a.name for a in sim.db.query(Anomaly).filter(Anomaly.event_id == event_id)}
                rows.append((names, label))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    parser.add_argument("--trials", type=int, default=8)
    args = parser.parse_args()

    rows = observations(args.seeds, args.trials)
    fires, hits = Counter(), Counter()
    for names, label in rows:
        for n in names:
            fires[n] += 1
            hits[n] += label
    attacks = sum(label for _, label in rows)
    print(f"{len(rows)} events from seeds {args.seeds}: {attacks} in attack trials, {len(rows) - attacks} normal or benign\n")

    rated = [n for n in standards.INDICATORS if fires[n]]
    unrated = sorted(n for n in fires if n not in standards.INDICATORS)
    names = rated + unrated
    X = np.array([[n in found for n in names] for found, _ in rows], dtype=float)
    y = np.array([label for _, label in rows])
    coef = dict(zip(names, LogisticRegression(C=1.0, max_iter=2000).fit(X, y).coef_[0])) if len(set(y)) == 2 else {}

    print(f"{'finding':<28}{'fired':>7}{'precision':>11}{'prior c':>9}{'gap':>7}{'log-odds':>10}")
    for n in names:
        precision = (hits[n] + 1) / (fires[n] + 2)
        prior = standards.INDICATORS[n].confidence if n in standards.INDICATORS else None
        gap = f"{precision - prior:+.2f}" if prior is not None else ""
        prior_s = f"{prior:.2f}" if prior is not None else "(ML)"
        print(f"{n:<28}{fires[n]:>7}{precision:>11.2f}{prior_s:>9}{gap:>7}{coef.get(n, float('nan')):>10.2f}")
    never = [n for n in standards.INDICATORS if not fires[n]]
    if never:
        print(f"\nNever fired in these scenarios (prior unchecked): {', '.join(never)}")


if __name__ == "__main__":
    main()
