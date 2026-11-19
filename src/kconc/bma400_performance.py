"""Paired latency for the BMA400 six-byte read, clustered by independent boot round."""
from collections import Counter
from itertools import combinations_with_replacement, permutations
import math
from statistics import fmean


ARMS = ("original", "cached", "skip-noop")
PHASES = {"warmup": 2, "measured": 4}
CALLS = 20000


def _cluster_interval(values):
    """Count the multiplicities of all ordered resamples of the complete rounds."""
    n = len(values)
    weighted = []
    for draw in combinations_with_replacement(range(n), n):
        weight = math.factorial(n) // math.prod(math.factorial(k) for k in Counter(draw).values())
        weighted.append((fmean(values[i] for i in draw), weight))
    weighted.sort()

    def at_rank(rank):
        cumulative = 0
        for value, weight in weighted:
            cumulative += weight
            if rank < cumulative:
                return value
        raise ValueError("rank exceeds resampling distribution")

    def quantile(p):
        index = p * (n**n - 1)
        low, high = at_rank(math.floor(index)), at_rank(math.ceil(index))
        return low + (high - low) * (index % 1)

    return [quantile(.025), quantile(.975)]


def _summarize_arm(pairs, arm, included):
    logs, savings, per_round = [], [], []
    for r in included:
        selected = [p["ns_per_call"] for p in pairs if p["round"] == r]
        ratio = fmean(math.log(s[arm] / s["original"]) for s in selected)
        saved = fmean(s["original"] - s[arm] for s in selected)
        logs.append(ratio)
        savings.append(saved)
        per_round.append({"round": r, "pairs": len(selected), "saved_ns": saved, "reduction_percent": -100 * math.expm1(ratio)})
    lo, hi = _cluster_interval(logs)
    return {
        "baseline": "original", "variant": arm, "pairs": len(included) * 4,
        "rounds": per_round, "bootstrap_draws": len(included)**len(included),
        "reduction_percent": -100 * math.expm1(fmean(logs)),
        "reduction_95_pct_interval": [-100 * math.expm1(hi), -100 * math.expm1(lo)],
        "saved_ns_per_call": fmean(savings), "saved_ns_per_call_95_interval": _cluster_interval(savings),
    }


def _distribution(values):
    ordered = sorted(values)
    def quantile(p):
        index = p * (len(ordered) - 1)
        a, b = ordered[math.floor(index)], ordered[math.ceil(index)]
        return a + (b - a) * (index % 1)
    return {"min": ordered[0], "p25": quantile(.25), "median": quantile(.5),
            "p75": quantile(.75), "max": ordered[-1], "mean": fmean(ordered)}


def summarize(rows, orders):
    """Consume identity-checked rows in their registered order. A missing slot excludes its entire round."""
    if len(orders) != 6 or {tuple(order) for order in orders} != set(permutations(ARMS)):
        raise ValueError("expected the six registered three-arm permutations")
    planned = [(r, arm, phase, batch) for r, order in enumerate(orders, 1) for arm in order
               for phase, count in PHASES.items() for batch in range(1, count + 1)]
    positions = {key: i for i, key in enumerate(planned)}
    observed = {}
    previous = -1
    for row in rows:
        key = row["round"], row["variant"], row["phase"], row["batch"]
        if type(key[0]) is not int or type(key[3]) is not int or key not in positions or positions[key] <= previous:
            raise ValueError("unregistered, duplicate or out-of-order batch")
        elapsed = row["elapsed_ns"]
        if type(row["calls"]) is not int or row["calls"] != CALLS or type(elapsed) is not int or elapsed <= 0:
            raise ValueError("invalid elapsed time or call count")
        observed[key] = elapsed
        previous = positions[key]

    missing = [key for key in planned if key not in observed]
    excluded = sorted({key[0] for key in missing})
    included = [r for r in range(1, 7) if r not in excluded]
    eligible = len(included) >= 5
    pairs = []
    for r in range(1, 7):
        for b in range(1, 5):
            elapsed = {a: observed.get((r, a, "measured", b)) for a in ARMS}
            pairs.append({"round": r, "batch": b, "included": eligible and r in included, "elapsed_ns": elapsed,
                          "ns_per_call": {a: x / CALLS if x is not None else None for a, x in elapsed.items()}})
    distributions = {
        a: _distribution([p["ns_per_call"][a] for p in pairs if p["included"]]) for a in ARMS
    } if eligible else {}
    comparisons = {}
    gate = None
    if eligible:
        for name, arm in (("primary", "skip-noop"), ("secondary", "cached")):
            comparisons[name] = _summarize_arm(pairs, arm, included)
        primary = comparisons["primary"]
        gate = primary["reduction_percent"] >= 5 and primary["reduction_95_pct_interval"][0] > 0
    return {"schema": 1, "eligible": eligible, "value_gate_passed": gate, "complete_rounds": included,
            "excluded_rounds": excluded, "missing_batches": [dict(zip(("round", "variant", "phase", "batch"), key)) for key in missing],
            "planned_batches": len(planned), "observed_batches": len(observed),
            "inference_pairs_per_comparison": len(included) * 4 if eligible else 0, "pairs": pairs,
            "units": "ns per full six-byte read", "distributions": distributions, "comparisons": comparisons,
            "method": "geometric mean of paired ratios; absolute paired difference; exact round-cluster percentile bootstrap"}
