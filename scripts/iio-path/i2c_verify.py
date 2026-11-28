"""Learn normal IIO paths and check one BMA400 I2C combined read per operation."""
import argparse
import sys
from pathlib import Path
import json
import re
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kconc import iio_path as iio


SCHEMA = "kconc.iio-bma400-i2c-pair.v1"
BUS_SEQUENCE = ("regmap_hw_read_start", "i2c_write", "i2c_read", "i2c_reply",
                "i2c_result", "regmap_hw_read_done", "regmap_bulk_read")
MESSAGE = re.compile(r"i2c-(\d+) #(\d+) a=([0-9a-fA-F]+) f=([0-9a-fA-F]+) l=(\d+)(?: \[([0-9a-fA-F-]+)\])?")
RESULT = re.compile(r"i2c-(\d+) n=(\d+) ret=(-?\d+)")
REGMAP = re.compile(r"(\d+)-([0-9a-fA-F]{4}) reg=((?:0x)?[0-9a-fA-F]+) (.*)")


def bus_events(lines, op):
    events = []
    for index in range(op.begin, op.end - 1):
        row = iio.FTRACE.search(lines[index])
        if row and int(row[1]) == op.tid and row[2].startswith(("regmap_", "i2c_")):
            events.append((index + 1, row[2], row[3].strip()))
    return events


def combined_read(events, value):
    """Associate the two messages and reply with the owning task's regmap access."""
    iio.require(tuple(row[1] for row in events) == BUS_SEQUENCE, "unexpected regmap/I2C event order")
    start, done, bulk = [REGMAP.fullmatch(events[i][2]) for i in (0, 5, 6)]
    iio.require(all((start, done, bulk)), "missing native I2C client or register in regmap trace")
    iio.require(start.groups()[:3] == done.groups()[:3] == bulk.groups()[:3],
                "regmap target changed during read")
    iio.require(start[4] == done[4] == "count=2", "regmap read has unexpected width")
    adapter, address, register = int(start[1]), int(start[2], 16), int(start[3], 16)
    write, read, reply = [MESSAGE.fullmatch(events[i][2]) for i in (1, 2, 3)]
    iio.require(all((write, read, reply)), "malformed I2C read or write")
    for msg in (write, read, reply):
        iio.require((int(msg[1]), int(msg[3], 16)) == (adapter, address), "wrong I2C client")
    iio.require(write[2] == "0" and write[5] == "1" and not int(write[4], 16) & 1
                and write[6] is not None and re.fullmatch(r"[0-9a-fA-F]{2}", write[6])
                and int(write[6], 16) == register, "wrong register selector")
    iio.require(read[2] == "1" and read[5] == "2" and int(read[4], 16) & 1 and read[6] is None
                and read.groups()[:5] == reply.groups()[:5], "wrong read request or reply")
    iio.require(reply[6] is not None and re.fullmatch(r"[0-9a-fA-F]{2}-[0-9a-fA-F]{2}", reply[6]),
                "missing two reply bytes")
    data = bytes.fromhex(reply[6].replace("-", " "))
    result = RESULT.fullmatch(events[4][2])
    iio.require(result is not None and (int(result[1]), result[2], result[3]) == (adapter, "2", "2"),
                "incomplete I2C transfer")
    iio.require(bulk[4].startswith("val=") and bytes.fromhex(bulk[4][4:]) == data,
                "regmap data differs from I2C reply")
    # In the native BMA400 driver the two-byte sample is little-endian with bit 11 as its sign.
    word = int.from_bytes(data, "little") & 0xfff
    decoded = word - 4096 if word & 0x800 else word
    iio.require(decoded == value, "I2C sample does not match the driver's returned value")
    return {"client": f"{adapter}-{address:04x}", "register": register,
            "write_flags": int(write[4], 16), "read_flags": int(read[4], 16),
            "reply_hex": data.hex(), "decoded": decoded,
            "trace_lines": {event: line for line, event, _ in events}}


def bus_shape(receipt, meta):
    # Values and returned bytes verify data delivery separately; neither classifies an operation.
    address = int(meta["i2c_address"], 16)
    client = f"{int(meta['i2c_adapter_nr'])}-{address:04x}"
    iio.require(meta["bus"] == "i2c" and receipt["client"] == meta["i2c_client"] == client,
                "operation belongs to a different device from the bound IIO client")
    # Linux assigns the adapter number at registration. Bind it within this boot, not across boots.
    return {"address": address, **{key: receipt[key] for key in ("register", "write_flags", "read_flags")}}


def run(args):
    meta, reads, hashes = iio.load_capture(args.capture)
    lines = (args.capture / "trace.txt").read_text(errors="replace").splitlines()
    if args.action == "discover":
        iio.require(meta["mode"] == "train", "discovery requires training mode")
        symbols = iio.project(meta, reads)
        ref = iio.train(meta, reads, hashes, symbols)
        bus, training = {}, []
        for op in reads.values():
            receipt = combined_read(bus_events(lines, op), op.value)
            shape = bus_shape(receipt, meta)
            iio.require(bus.setdefault(op.axis, shape) == shape, "unstable I2C training signature")
            training.append({"key": op.key, "axis": op.axis, "tid": op.tid, **receipt})
        iio.require(bus["X"]["register"] != bus["Y"]["register"], "I2C selectors do not distinguish axes")
        ref.update(schema=SCHEMA, bus_signature=bus, bus_training=training)
        ref["certificate_sha256"] = iio.digest_json(ref)
        return ref

    ref = iio.read_json(args.reference)
    seal = ref.pop("certificate_sha256")
    iio.require(ref["schema"] == SCHEMA and seal == iio.digest_json(ref), "invalid reference")
    iio.require(ref["identity"] == iio.identity(meta) and ref["training_boot_id"] != meta["boot_id"],
                "target build mismatch or training boot reused")
    selected = {key: reads[key] for key in args.keys}
    iio.require(len(selected) == 2 and len({op.tid for op in selected.values()}) == 2,
                "pair must have two distinct keys and worker threads")
    iio.project(meta, selected, ref["symbols"])
    pair = list(selected.values())
    original = iio.compare(ref, pair, args.order)
    original.update(boot_id=meta["boot_id"], identity=iio.identity(meta), order=args.order,
                    reference_sha256=seal, capture_raw_sha256=hashes)
    for observation, op, axis in zip(original["observations"], pair, args.order):
        receipt = combined_read(bus_events(lines, op), op.value)
        observed_shape = bus_shape(receipt, meta)
        matches = [kind for kind, shape in ref["bus_signature"].items() if shape == observed_shape]
        observation.update(i2c=receipt, identified_by_i2c=matches)
        if matches != [axis]:
            original["reasons"].append(f"{op.key}: I2C selector or client differs from {axis}")
    original["passed"] = not original["reasons"]
    if args.action == "verify":
        return original

    iio.require(original["passed"], "negative control requires a matching original pair")
    negative = iio.negative_checks(ref, pair, args.order)
    # Exchange real read-request/reply lines on a copy, leaving all four IIO boundaries in place.
    positions = original["observations"][0]["i2c"]["trace_lines"]
    a, b = positions["i2c_read"] - 1, positions["i2c_reply"] - 1
    altered = lines.copy()
    altered[a], altered[b] = altered[b], altered[a]
    try:
        combined_read(bus_events(altered, pair[0]), pair[0].value)
    except ValueError as error:
        diagnostic = str(error)
    else:
        diagnostic = None
    negative.update(boot_id=meta["boot_id"], order=args.order, reference_sha256=seal,
                    capture_raw_sha256=hashes,
                    swapped_i2c_events={"rejected": diagnostic is not None, "reason": diagnostic,
                                        "swapped_lines": [a + 1, b + 1],
                                        "original_lines": [lines[a], lines[b]],
                                        "unchanged_return_lines": [lines[op.end - 1] for op in pair]})
    negative["passed"] = negative["passed"] and diagnostic is not None
    return negative


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for name in ("discover", "verify", "negative"):
        command = sub.add_parser(name)
        command.add_argument("--capture", type=Path, required=True)
        command.add_argument("--out", type=Path, required=True)
        if name != "discover":
            command.add_argument("--reference", type=Path, required=True)
            command.add_argument("--order", choices=("XY", "YX"), required=True)
            command.add_argument("--keys", nargs=2, required=True)
    args = parser.parse_args()
    try:
        result = run(args)
    except (KeyError, ValueError, OSError, subprocess.SubprocessError) as error:
        result = {"passed": False, "diagnostic": str(error)}
    with args.out.open("x", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return int(not result.get("passed", args.action == "discover" and "certificate_sha256" in result))


if __name__ == "__main__":
    sys.exit(main())
