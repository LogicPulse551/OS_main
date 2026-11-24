"""Bounded schedules and a register-state oracle for the private RAM regmap fixture."""
from collections import Counter, deque
from functools import lru_cache
from math import gcd, lcm


def _threads(value):
    if type(value) is not int or not 2 <= value <= 5:
        raise ValueError("threads must be an integer from 2 to 5")


def _after(remaining, role):
    return remaining[:role] + (remaining[role] - 1,) + remaining[role + 1:]


@lru_cache(maxsize=None)
def _count(remaining, last, switches):
    """Number of suffixes with exactly this many further changes of role."""
    if switches < 0 or switches > sum(remaining):
        return 0
    if not any(remaining):
        return int(switches == 0)
    return sum(_count(_after(remaining, role), role, switches - (role != last))
               for role, left in enumerate(remaining) if left)


def _order(threads, first, depth, rank):
    remaining = _after((2,) * threads, first)
    order = [first]
    while any(remaining):
        for role, left in enumerate(remaining):
            if not left:
                continue
            rest = _after(remaining, role)
            new_depth = depth - (role != order[-1])
            count = _count(rest, role, new_depth)
            if rank < count:
                order.append(role)
                remaining, depth = rest, new_depth
                break
            rank -= count
        else:
            raise AssertionError("rank exceeds the number of schedules")
    return order


def _round_robin_rank(threads, first):
    """Rank two complete rotations within the fixed first-role, maximum-depth stratum."""
    remaining = _after((2,) * threads, first)
    last, depth, rank = first, 2 * threads - 1, 0
    for step in range(1, 2 * threads):
        chosen = (first + step) % threads
        for role in range(chosen):
            if remaining[role]:
                rank += _count(_after(remaining, role), role, depth - (role != last))
        remaining = _after(remaining, chosen)
        depth -= chosen != last
        last = chosen
    return rank


class _Orders:
    """Restartable stream. Keep one cursor per (depth, first role)."""

    def __init__(self, threads, strata, selected):
        self.threads = threads
        self.strata = strata
        self.selected = selected

    def __len__(self):
        return self.selected

    def __iter__(self):
        queue = deque(self.strata)
        for _ in range(self.selected):
            depth, first, size, rank, stride, left = queue.popleft()
            yield _order(self.threads, first, depth, rank)
            if left > 1:
                queue.append((depth, first, size, (rank + stride) % size, stride, left - 1))


def plan_cases(threads, max_switches, budget=None):
    """Count all schedules and stream a reproducible prefix of the eligible ones.

    Depth counts changes of role between consecutive completed API operations.
    Every role sets its own bit on its first operation and clears it on its second.
    A budget of None selects every eligible schedule. Zero selects none.
    """
    _threads(threads)
    if type(max_switches) is not int or max_switches < 0:
        raise ValueError("max_switches must be a nonnegative integer")
    if budget is not None and (type(budget) is not int or budget < 0):
        raise ValueError("budget must be a nonnegative integer or None")
    # Relabelling the first role gives equally many schedules for each first role.
    remaining = _after((2,) * threads, 0)
    counts = {d: threads * _count(remaining, 0, d) for d in range(threads - 1, 2 * threads)}
    eligible = deque(d for d in counts if d <= max_switches)
    total = sum(counts[d] for d in eligible)
    selected = total if budget is None else min(budget, total)

    # Start at the requested depth, then the shallow baseline, then move inward.
    depths = []
    while eligible:
        depths.append(eligible.pop())
        if eligible:
            depths.append(eligible.popleft())
    strata = []
    if depths:
        period = lcm(len(depths), threads)
        for index in range(len(depths) * threads):
            depth = depths[index % len(depths)]
            first = (index + index // period) % threads
            size = counts[depth] // threads
            # A coprime stride visits each lexical rank exactly once. A short budget
            # therefore samples distinct prefixes without materializing permutations.
            stride = max(1, size // 2)
            while gcd(stride, size) != 1:
                stride += 1
            # The deepest baseline reaches the all-bits-set state before clearing.
            # The shallowest lexical rank keeps the operations of each role together.
            start = _round_robin_rank(threads, first) if depth == 2 * threads - 1 else 0
            strata.append((depth, first, size, start, stride, size))
    return dict(threads=threads, max_switches=max_switches, budget=budget,
                counts_by_depth=counts, total_eligible=total, selected=selected,
                unexplored=total - selected, orders=_Orders(threads, strata, selected))


def verify_case(threads, order, rows, final):
    """Match each update with its planned role, worker PID and expected RAM value."""
    _threads(threads)
    if not isinstance(order, (tuple, list)) or len(order) != 2 * threads:
        raise ValueError("expected two operations per role")
    if any(type(role) is not int or not 0 <= role < threads for role in order):
        raise ValueError("invalid role in schedule")
    if Counter(order) != {role: 2 for role in range(threads)}:
        raise ValueError("each role must occur exactly twice")
    if not isinstance(rows, (tuple, list)) or len(rows) != len(order):
        raise ValueError("observation count differs from schedule")
    pids = {}
    value = 0
    for step, (role, row) in enumerate(zip(order, rows)):
        if not isinstance(row, dict) or any(type(row.get(field)) is not int
                                            for field in ("step", "role", "pid", "before", "after", "rc")):
            raise ValueError(f"step {step}: incomplete integer observation")
        if (row["step"], row["role"]) != (step, role):
            raise ValueError(f"step {step}: actual order differs from schedule")
        pid = row["pid"]
        if pid <= 0 or (role in pids and pids[role] != pid) or (role not in pids and pid in pids.values()):
            raise ValueError(f"step {step}: inconsistent role/PID binding")
        updated = value & ~(1 << role) if role in pids else value | (1 << role)
        if row["rc"] != 0:
            raise ValueError(f"step {step}: regmap update returned {row['rc']}")
        if (row["before"], row["after"]) != (value, updated):
            raise ValueError(f"step {step}: expected register {value} -> {updated}, "
                             f"observed {row['before']} -> {row['after']}")
        pids[role] = pid
        value = updated
    if type(final) is not int or final != value:
        raise ValueError(f"final readback differs from expected register {value}")
    return dict(status="passed", threads=threads, switches=sum(a != b for a, b in zip(order, order[1:])),
                final=final, steps=len(rows), pids={str(role): pid for role, pid in pids.items()})
