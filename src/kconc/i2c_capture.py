"""Compare two ordered, single combined I2C reads in sealed regmap captures."""
import re
from uuid import UUID

from .iio_path import FTRACE, require, sha_file

MARK = re.compile(r"(IIO|HWMON)_(BEGIN|END) key=([\w-]+) (axis|channel)=([\w-]+)(?: rc=(-?\d+) value=(-?\d+))?")
REG = re.compile(r"(\d+)-([0-9a-fA-F]+) reg=((?:0x)?[0-9a-fA-F]+) count=(\d+)")
MSG = re.compile(r"i2c-(\d+) #(\d+) a=([0-9a-fA-F]+) f=([0-9a-fA-F]+) l=(\d+)(?: \[([0-9a-fA-F-]+)\])?")
RESULT = re.compile(r"i2c-(\d+) n=(\d+) ret=(-?\d+)")
SEQUENCE = ("regmap_hw_read_start", "i2c_write", "i2c_read", "i2c_reply", "i2c_result", "regmap_hw_read_done")


def sealed(cap):
    """Read only fixed filenames; the serial seal binds the actual guest inventory."""
    entries = {}
    inventory = cap / "capture.sha256"
    for row in inventory.read_text(encoding="ascii").splitlines():
        checksum, name = row.split("  ", 1)
        require(name not in entries and re.fullmatch("[a-f0-9]{64}", checksum), "invalid capture inventory")
        entries[name] = checksum
    seal = sha_file(inventory)
    serial = (cap / "serial.log").read_text(errors="replace").splitlines()
    require(serial.count("CAPTURE " + seal + "  capture.sha256") == 1,
            "guest serial does not confirm the inventory")
    names = ["kernel.notes", "board.notes", "run.env", "stats.txt", "trace.txt", "ops.tsv"]
    if "driver.notes" in entries:
        names.append("driver.notes")
    for name in names:
        require(sha_file(cap / name) == entries.get(name), "capture differs: " + name)
    env = {}
    for row in (cap / "run.env").read_text().splitlines():
        key, value = row.split("=", 1)
        require(key not in env, "duplicate environment field")
        env[key] = value
    require(env["bus"] == "i2c" and env["cleaned"] == "1", "incomplete I2C observation")
    require([s[5:] for s in serial if s.startswith("BOOT ")] == [env["boot_id"]], "serial and run.env disagree on boot")
    subsystems = [name for name in ("iio", "hwmon") if env.get(name + "_name")]
    require(len(subsystems) == 1, "expected one IIO or hwmon identity")
    subsystem = subsystems[0]
    require(not env.get("driver_module") or "driver.notes" in entries, "missing loadable driver identity")
    identity = {name: entries[name] for name in names if name.endswith(".notes")}
    identity.update(subsystem=subsystem, sensor=env[subsystem + "_name"], driver=env["bound_driver"],
                    board=env["board_module"], address=int(env["i2c_address"], 16))
    if subsystem == "hwmon":
        identity["attributes"] = [env["channel_a"], env["channel_b"]]
    dropped = re.findall(r"^(?:overrun|commit overrun|dropped events):\s*(\d+)", (cap / "stats.txt").read_text(), re.M)
    require(dropped and not any(map(int, dropped)), "missing stats or dropped events")
    return seal, env, identity


def transfer(events, bus, addr):
    require(tuple(name for _, name, _ in events) == SEQUENCE, "combined request/reply event order differs")
    start, done = [REG.fullmatch(events[i][2]) for i in (0,5)]
    require(start and done and start.groups() == done.groups(), "regmap access changed during transfer")
    bus_no, dev, register, count = start.groups()
    reg = int(register, 16)
    require((int(bus_no), int(dev, 16)) == (bus, addr) and int(count) > 0, "wrong regmap client")
    write, read, reply = [MSG.fullmatch(events[i][2]) for i in (1,2,3)]
    require(all((write, read, reply)) and all((int(x[1]), int(x[3],16)) == (bus,addr) for x in (write,read,reply)),
            "I2C message belongs to different adapter or client")
    require(write[2] == "0" and write[5] == "1" and not int(write[4],16)&1 and write[6]
            and re.fullmatch(r"[a-fA-F0-9]{2}",write[6]) and int(write[6],16) == reg, "wrong I2C selector")
    require(read[2] == "1" and int(read[4],16)&1 and read[6] is None and read.groups()[:5] == reply.groups()[:5]
            and re.fullmatch(r"(?:[a-fA-F0-9]{2}-)*[a-fA-F0-9]{2}",reply[6] or ""), "inconsistent I2C read/reply")
    require(len(reply[6].split("-")) == int(read[5]), "I2C byte count mismatch")
    result = RESULT.fullmatch(events[4][2])
    require(result and (int(result[1]),int(result[2]),int(result[3])) == (bus,2,2), "incomplete combined transfer")
    return {"register":reg, "count":int(count), "bytes":int(read[5]), "write_flags":int(write[4],16),
            "read_flags":int(read[4],16)}, reply[6]


def operations(cap, keys, env, identity):
    require(len(set(keys)) == 2, "choose two different operation keys")
    reads = {}
    for line in (cap / "ops.tsv").read_text().splitlines():
        fields = line.split("\t")
        if fields[0] not in keys:
            continue
        key, label = fields[:2]
        require(len(fields) == (7 if identity["subsystem"]=="iio" else 6) and key not in reads, "invalid operation table")
        tid, size, error, value = map(int, fields[2:6])
        require(tid > 0 and size > 0 and error == 0, "operation did not return a reading")
        reads[key] = {"key":key, "label":label, "tid":tid, "value":value, "events":[]}
    require(set(keys) == set(reads) and len({r["tid"] for r in reads.values()}) == 2, "expected two worker TIDs")
    require(len({r["label"] for r in reads.values()}) == 2, "expected separate channels")
    active = {}
    for number, text in enumerate((cap / "trace.txt").read_text(errors="strict").splitlines(), 1):
        require("LOST EVENTS" not in text.upper(), "lost ftrace events")
        row = FTRACE.search(text)
        if not row:
            continue
        tid, event, payload = int(row[1]), row[2], row[3].strip()
        if event in ("tracing_mark_write","trace_marker") and (marker := MARK.fullmatch(payload)):
            subsystem, edge, key, label_kind, label, rc, value = marker.groups()
            if key not in reads:
                require(tid not in active, "another marked read inside a selected operation")
                continue
            r = reads[key]
            require(subsystem.lower() == identity["subsystem"] and label_kind == ("axis" if subsystem=="IIO" else "channel")
                    and (label,tid) == (r["label"],r["tid"]), "operation marker identity differs")
            if edge == "BEGIN":
                require(tid not in active and "begin" not in r and rc is None, "unexpected start")
                active[tid] = r
                r["begin"] = number
            else:
                require(active.get(tid) is r and rc == "0" and value is not None and int(value) == r["value"],
                        "operation return differs from ops.tsv")
                del active[tid]
                r["end"] = number
        elif tid in active and (event.startswith(("i2c_", "smbus_")) or event in SEQUENCE):
            active[tid]["events"].append((number,event,payload))
    result = [reads[k] for k in keys]
    for r in result:
        require("begin" in r and "end" in r, "incomplete operation interval")
        events = r.pop("events")
        r["shape"], r["reply_hex"] = transfer(events,int(env["i2c_adapter_nr"]),identity["address"])
        r["trace_lines"] = {event:line for line,event,_ in events}
    require(result[0]["end"] < result[1]["begin"], "requested complete-operation order differed or overlapped")
    require(result[0]["shape"] != result[1]["shape"], "bus signatures cannot distinguish these channels")
    return result


def compare(reference, keys, capture, actual_keys):
    baseline_seal, baseline_env, baseline_id = sealed(reference)
    current_seal, current_env, current_id = sealed(capture)
    output = {"scope":"archived, complete two-message I2C reads", "reference_seal":baseline_seal,
              "capture_seal":current_seal, "matched":False, "reference_boot_id":str(UUID(baseline_env["boot_id"])),
              "boot_id":str(UUID(current_env["boot_id"])), "identity":current_id}
    baseline = operations(reference,keys,baseline_env,baseline_id)
    output["reference_operations"] = baseline
    try:
        require(baseline_id == current_id, "hardware or build identity differs")
        require(output["reference_boot_id"] != output["boot_id"], "expected a separate boot for verification")
        actual = operations(capture,actual_keys,current_env,current_id)
        output["operations"] = actual
        require([(r["label"],r["shape"]) for r in baseline] == [(r["label"],r["shape"]) for r in actual],
                "channel or intermediate transfer differs from reference")
        output["matched"] = True
    except ValueError as exc:
        output["reason"] = str(exc)
    return output
