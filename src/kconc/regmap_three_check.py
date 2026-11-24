"""Recount one resettable, three-caller RAM regmap observation from its kernel log."""
import argparse
import hashlib
from html import escape
import json
from pathlib import Path
import re


BITS = {"A": 1, "B": 2, "C": 4}
KINDS = ("ENTER", "READ", "WRITE", "EXIT")
TAGS = {
    "BEGIN": re.compile(r"property=(update|mutex) variant=(normal|fault|fixed) order=(ABC|ACB) initial=0"),
    "EVENT": re.compile(r"seq=(\d+) role=([ABC]) tid=(\d+) kind=(ENTER|READ|WRITE|EXIT) reg=0 value=(\d+)"),
    "THREAD": re.compile(r"role=([ABC]) tid=(\d+) rc=0"),
    "READBACK": re.compile(r"tid=(\d+) reg=0 value=(\d+) rc=0"),
    "END": re.compile(r"final=(\d+) ok=1"),
    "CLEAN": re.compile(r""),
}
LOG_LINE = re.compile(r"^(?:<\d+>)?(?:\[\s*\d+\.\d+\]\s*)?TRI_([A-Z_]+)(?: (.*))?$")
SGR = re.compile(r"\x1b\[[0-9;]*m")


def require(ok, diagnostic):
    if not ok:
        raise ValueError(diagnostic)


def records(lines):
    for line_no, line in enumerate(lines.splitlines() if isinstance(lines, str) else lines, 1):
        line = SGR.sub("", line.strip())
        if "TRI_" not in line:
            continue
        match = LOG_LINE.fullmatch(line)
        require(match is not None, f"unrecognized record prefix at line {line_no}")
        tag, text = match.groups()
        fields = TAGS[tag].fullmatch(text or "") if tag in TAGS else None
        require(fields is not None, f"malformed {tag} at line {line_no}")
        yield tag, fields.groups(), line_no


def schedule(prop, variant, order):
    if variant != "fault":
        return [(role, kind) for role in order for kind in KINDS]
    split = 2 if prop == "update" else 1
    return [(role, kind) for phase in (KINDS[:split], KINDS[split:]) for role in order for kind in phase]


def update_state(events, final):
    current = 0
    reads, writes = {}, {}
    erased = []
    for event in events:
        role, kind, value, seq = (event[k] for k in ("role", "kind", "value", "seq"))
        if kind == "READ":
            require(role not in reads, "repeated RAM read")
            require(value == current, f"{role} READ differs from the preceding RAM state")
            reads[role] = value
        elif kind == "WRITE":
            require(role in reads and role not in writes, "write without one matching worker read")
            require(value == reads[role] | BITS[role], f"{role} WRITE does not set its bit on its actual read")
            for owner, bit in BITS.items():
                if current & bit and not value & bit:
                    erased.append({"lost_role": owner, "writer": role, "seq": seq,
                                   "before_write": current, "read_by_writer": reads[role], "after_write": value})
            current = value
            writes[role] = value
    require(set(writes) == set(BITS), "incomplete RAM updates")
    require(current == final, "independent readback differs from last RAM write")
    return dict(expected=sum(BITS.values()), observed=final, missing_roles=[r for r in BITS if not final & BITS[r]],
                overwritten=erased, read=reads, write=writes, violated=final != sum(BITS.values()))


def mutex_intervals(events):
    inside, intervals = {}, {}
    overlaps = []
    depth = 0
    for event in events:
        role, kind, seq = (event[k] for k in ("role", "kind", "seq"))
        if kind == "ENTER":
            require(event["value"] == 0 and role not in inside and role not in intervals, "invalid ENTER")
            overlaps.extend({"roles": [other, role], "entered_at": seq} for other in inside)
            inside[role] = seq
            depth = max(depth, len(inside))
        elif kind == "EXIT":
            require(event["value"] == 0 and role in inside, "invalid EXIT")
            intervals[role] = [inside.pop(role), seq]
    require(not inside and set(intervals) == set(BITS), "incomplete critical section intervals")
    return dict(intervals=intervals, peak=depth, overlapping=overlaps, violated=bool(overlaps))


def parse(lines, property, variant, order):
    """Accept a single completed load/unload, including its independent final read."""
    requested = (property, variant, order)
    empty = dict(property=property, variant=variant, order=order, complete=False, matched=False,
                 violation=None, eligible_witness=False)
    try:
        rows = list(records(lines))
        require(rows and rows[0][:2] == ("BEGIN", requested), "missing or mismatched case header")
        require(len(rows) == 19 and [tag for tag, _, _ in rows[-3:]] == ["READBACK", "END", "CLEAN"],
                "incomplete execution, readback or cleanup")
        events, tids, exits = [], {}, {}
        steps = {role: [] for role in BITS}
        for tag, fields, line_no in rows[1:-3]:
            if tag == "THREAD":
                role, tid = fields
                require(role not in exits and steps[role] == list(KINDS), "missing work or duplicate thread return")
                exits[role] = int(tid)
                continue
            require(tag == "EVENT", "unexpected record in worker trace")
            seq, role, tid, kind, value = fields
            seq, tid, value = int(seq), int(tid), int(value)
            require(seq == len(events) + 1 and tid > 0 and value <= 0xffffffff, "event seq, tid or value invalid")
            require(tids.setdefault(role, tid) == tid, "worker identity changed")
            steps[role].append(kind)
            events.append(dict(seq=seq, role=role, tid=tid, kind=kind, reg=0, value=value, line=line_no))
        require(all(steps[role] == list(KINDS) for role in BITS), "worker has missing or misordered events")
        require(len(set(tids.values())) == 3 and exits == tids, "worker identities or return receipts differ")
        reader, final = map(int, rows[-3][1])
        require(reader > 0 and reader not in tids.values(), "readback requires an independent reader")
        require(final == int(rows[-2][1][0]), "readback and end disagree")
        update, mutex = update_state(events, final), mutex_intervals(events)
        matched = [(e["role"], e["kind"]) for e in events] == schedule(*requested)
        violation = (update if property == "update" else mutex)["violated"]
        path = [[e["role"], e["kind"], e["reg"], e["value"]] for e in events]
        return dict(empty, complete=True, matched=matched, violation=violation,
                    eligible_witness=matched and violation, diagnostic=None if matched else "candidate order differs",
                    role_tids=tids, reader_tid=reader, final=final, update=update, mutex=mutex, events=events, path=path)
    except ValueError as error:
        return dict(empty, diagnostic=str(error))


def replay(reference, current, reference_build, current_build):
    """Caller supplies identities verified against the guest kernel and loaded module."""
    if not reference_build or not current_build or reference_build != current_build:
        reason = "missing or different build identity"
    elif not all(r.get("complete") and r.get("matched") for r in (reference, current)):
        reason = "invalid or off-candidate trace"
    elif any(reference[k] != current[k] for k in ("property", "variant", "order", "final", "violation", "path")):
        reason = "case or intermediate path differs"
    else:
        reason = None
    return dict(matched=reason is None, diagnostic=reason)


def write_html(path, result, title="三线程 regmap 执行见证", comparison=None):
    def td(value):
        return "<td>" + escape(str(value)) + "</td>"

    def table(headers, values):
        return "<table><thead><tr>" + "".join("<th>"+escape(h)+"</th>" for h in headers) + "</tr></thead><tbody>" + "".join(
            "<tr>"+"".join(td(v) for v in row)+"</tr>" for row in values) + "</tbody></table>"

    h = escape(title)
    parts = ['<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">',
             f"<title>{h}</title><style>body{{font:16px/1.6 system-ui;max-width:60em;margin:2em auto;padding:0 1em}}"
             "table{border-collapse:collapse}td,th{padding:.3em .8em;border:1px solid #aab4bf;text-align:left}th{background:#edf2f4}</style>",
             f"<h1>{h}</h1>", "<p>"+escape(f"{result['property']} / {result['variant']} / {result['order']}")+"</p>"]
    if "source" in result:
        source = result["source"]
        parts.append("<p>串口文件 "+escape(source["name"])+"，SHA-256 <code>"+escape(source["sha256"])+"</code>。"
                     +escape(f"区段从第 {result['begin_line']} 行开始。")+"</p>")
    if not result["complete"]:
        parts.append("<p>记录无效。"+escape(result["diagnostic"])+"</p>")
    else:
        u, m = result["update"], result["mutex"]
        parts.append("<p>候选"+("命中" if result["matched"] else "偏离")+"。指定性质"+("出现违例" if result["violation"] else "通过")+"。</p>")
        parts.append("<p>"+escape(f"独立线程 {result['reader_tid']} 最终读到 {result['final']}，应保留的三位合计 {u['expected']}。同时处于临界区的线程峰值为 {m['peak']}。")+"</p>")
        if u["overwritten"]:
            parts.append("<h2>覆盖先前更新的写入</h2>"+table(["被清除位的角色","覆盖者","事件","覆盖者先前读值","写入前的总线值","写入后的总线值"],
                         ([r[k] for k in ("lost_role","writer","seq","read_by_writer","before_write","after_write")] for r in u["overwritten"])))
        if m["overlapping"]:
            parts.append("<h2>临界区重叠</h2>"+table(["角色","两个区间首次重叠的事件"],
                         (("、".join(r["roles"]),r["entered_at"]) for r in m["overlapping"])))
        parts.append("<h2>实际事件</h2>"+table(["序号","角色","线程 TID","动作","寄存器","记录值","输入行"],
                     ([e[k] for k in ("seq","role","tid","kind","reg","value","line")] for e in result["events"])))
    if comparison is not None:
        parts.append("<p>同构建路径重放"+("匹配" if comparison["matched"] else "未匹配")+"。</p>")
    with Path(path).open("x", encoding="utf-8") as f:
        f.write("\n".join(parts)+"\n</html>\n")


CASE_KEY = re.compile(r"(update|mutex) (normal|fault|fixed) (ABC|ACB)")


def case_reports(lines):
    """Preserve every started case, including a section cut short by a later one."""
    stream = lines.splitlines() if isinstance(lines, str) else list(lines)
    cases, errors = [], []
    key, start = None, None

    def finish(end, error=None):
        result = parse(stream[start:end - 1], *key)
        if error:
            result = dict(property=key[0], variant=key[1], order=key[2], complete=False, matched=False,
                          violation=None, eligible_witness=False, diagnostic=error)
        for event in result.get("events", []):
            event["line"] += start
        result.update(ordinal=len(cases) + 1, begin_line=start, end_line=None if error else end)
        cases.append(result)

    for line_no, line in enumerate(stream, 1):
        words = line.strip().split(maxsplit=1)
        if not words:
            continue
        marker = words[0]
        payload = words[1] if len(words) > 1 else ""
        if marker == "CASE_BEGIN":
            if key is not None:
                finish(line_no, "missing CASE_END before next case")
                key = None
            header = CASE_KEY.fullmatch(payload)
            if header:
                key, start = header.groups(), line_no
            else:
                errors.append(f"malformed CASE_BEGIN at line {line_no}")
        elif marker == "CASE_END":
            if key is None:
                errors.append(f"orphan CASE_END at line {line_no}")
            else:
                finish(line_no, "unexpected CASE_END fields" if payload else None)
                key = None
        elif key is None and LOG_LINE.fullmatch(SGR.sub("", line.strip())):
            errors.append(f"kernel case record outside CASE_BEGIN/CASE_END at line {line_no}")
    if key is not None:
        finish(len(stream) + 1, "missing CASE_END at end of input")
    if not cases:
        errors.append("no cases found")
    return cases, errors


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check the recorded three-worker RAM regmap fixture in a guest serial log.",
                                     epilog="Exit 0 means each selected execution was complete and on its requested path. "
                                            "Each execution reports its property violation separately.")
    parser.add_argument("serial", type=Path)
    parser.add_argument("--property", choices=("update", "mutex"))
    parser.add_argument("--variant", choices=("normal", "fault", "fixed"))
    parser.add_argument("--order", choices=("ABC", "ACB"))
    parser.add_argument("--html-dir", type=Path, help="new directory for one report per selected case")
    args = parser.parse_args(argv)
    try:
        raw = args.serial.read_bytes()
        source_hash = hashlib.sha256(raw).hexdigest()
        all_cases, errors = case_reports(raw.decode("utf-8", errors="replace"))
        cases = [case for case in all_cases if all(getattr(args, field) in (None, case[field])
                  for field in ("property", "variant", "order"))]
        if not cases and all_cases:
            errors.append("no cases matched the requested selection")
        if args.html_dir and cases:
            args.html_dir.mkdir(parents=True, exist_ok=False)
            for case in cases:
                name = "{ordinal:03}-{property}-{variant}-{order}.html".format(**case)
                write_html(args.html_dir / name, dict(case, source=dict(name=args.serial.name, sha256=source_hash)))
        summary = dict(serial=str(args.serial), sha256=source_hash,
                       total_cases=len(all_cases), selected=len(cases), cases=cases, errors=errors)
        print(json.dumps(summary, indent=2))
        return 0 if not errors and all(case["complete"] and case["matched"] for case in cases) else 1
    except OSError as error:
        parser.exit(2, f"{parser.prog}: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
