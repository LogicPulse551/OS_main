"""Boot the registered two-worker RAM regmap update and check its lock handoff."""
from pathlib import Path
import re
import subprocess

from .cli import OperationError, digest, json_object, now, save
from .regmap_two_prelock_check import BUILD_ID, PLAN_SHA256, check_slot


# The disk is the distributor's unmodified openEuler image, opened read-only.
IMAGE_HASHES = {
    "kernel": "95f7a3285fee19394a2022f6cc5b5af95b874e8a7298c81b22584fc1f7690644",
    "config": "ec06c5043608115d0f8b5ab3ef7fd0c9afd99ea6c1df4ba859345f833b0613b7",
    "initrd": "bf5eb42f74a4ebe0bbd6845605d73f094200c6a259a743b91462a1711d0f62bf",
    "disk": "3f1c7ef7a553db3137ed3b9b45294d52869c3bb63c1d30aa3b66bbe02ee2ce89",
    "plan": PLAN_SHA256,
}
HOUSEKEEPING_ARGS = "isolcpus=domain,managed_irq,0-1 irqaffinity=2-3"
SEALED_FILES = {
    "kernel.notes", "system.trace", "probes.txt", "backend.exit", "backend.out",
    "backend.err", "native/plan.txt", "native/run.json", "native/run.partial.json",
    "native/testcase.stdout.txt", "native/testcase.stderr.txt", "native/A.words",
    "native/B.words", "native/A.events.jsonl", "native/B.events.jsonl",
}


def require(ok, reason):
    if not ok:
        raise OperationError("prelock_evidence", reason)


def registered_files(bundle, disk):
    paths = {"kernel": bundle / "bzImage", "config": bundle / "config",
             "initrd": bundle / "initrd.gz", "plan": bundle / "plan.txt", "disk": disk}
    for name, path in paths.items():
        require(path.is_file() and digest(path) == IMAGE_HASHES[name],
                f"Registered {name} missing or changed: {path}")
    return paths


def check_guest_timer(lines, expected_active=0):
    cmdlines = [line.removeprefix("TIMER_CMDLINE ").split() for line in lines if line.startswith("TIMER_CMDLINE ")]
    expected_parameters = [] if expected_active else ["highres=off"]
    require(len(cmdlines) == 1 and [token for token in cmdlines[0] if token.startswith("highres=")] == expected_parameters,
            "Guest did not confirm its registered timer configuration")
    observed = {"before": set(), "after": set()}
    for line in lines:
        if not line.startswith("TIMER_MODE"):
            continue
        reading = re.fullmatch(rf"TIMER_MODE phase=(before|after) cpu=([0-3]) hres_active={expected_active}", line)
        require(reading is not None, "Invalid per-CPU guest timer reading")
        phase, cpu = reading.groups()
        require(phase != "before" or not observed["after"], "Guest timer phases out of order")
        observed[phase].add(cpu)
    require(all(cpus == set("0123") for cpus in observed.values()), "Missing per-CPU guest timer readings")


def check_housekeeping(lines):
    cmdlines = [line.split()[1:] for line in lines if line.startswith("TIMER_CMDLINE ")]
    require(len(cmdlines) == 1 and [word for word in cmdlines[0] if word.startswith(("isolcpus=", "irqaffinity="))]
            == HOUSEKEEPING_ARGS.split(), "Guest did not confirm scheduling and IRQ boot parameters")
    phases = []
    for line in lines:
        if line.startswith("GUEST_HOUSEKEEPING "):
            match = re.fullmatch(r"GUEST_HOUSEKEEPING phase=(before|after) isolated=0-1 irq_default=([0-9a-fA-F]{1,8}(?:,[0-9a-fA-F]{8})*)", line)
            require(match and int(match[2].replace(",", ""), 16) == 12, "Guest isolation or IRQ default differs")
            phases.append(match[1])
    require(phases == ["before", "after"], "Missing or out-of-order guest housekeeping readback")


def checked_capture(slot, plan, order="ab", timer=None, placement=None, housekeeping=None):
    serial = (slot / "serial.log").read_text().splitlines()
    if timer == "lowres":
        check_guest_timer(serial)
    if placement == "pinned-vcpus":
        from .prelock_vcpu_placement import check_receipt
        check_guest_timer(serial, expected_active=1)
        check_receipt(json_object(slot / "host-placement.json"))
    if housekeeping:
        check_housekeeping(serial)
    for line in ("normal.so: OK", "sampler: OK", "plan.txt: OK", "K14_SUPERVISOR_EXIT 0"):
        require(serial.count(line) == 1, f"Missing or ambiguous serial receipt: {line}")
    raw = slot / "raw"
    inventory = raw / "files.sha256"
    seals = [line for line in serial if line.startswith("CAPTURE ")]
    require(seals == [f"CAPTURE {digest(inventory)}  files.sha256"], "Guest capture seal differs")
    seen = set()
    for line in inventory.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  \./(.+)", line)
        require(match is not None, "Invalid guest file inventory")
        expected, name = match.groups()
        require(name in SEALED_FILES and name not in seen, f"Unexpected guest file: {name}")
        require(digest(raw / name) == expected, f"Guest file digest differs: {name}")
        seen.add(name)
    require(seen == SEALED_FILES, "Incomplete guest evidence inventory")
    require((raw / "backend.exit").read_text().strip() == "0", "Guest executor failed")
    try:
        return check_slot(slot, plan, direction=order)
    except ValueError as exc:
        raise OperationError("handoff_mismatch", str(exc)) from exc


def accepted_reference(directory, plan, order, identities, timer=None, placement=None, housekeeping=None):
    result_path = directory / "result.json"
    witness_path = directory / "witness.json"
    require(result_path.is_file() and witness_path.is_file(), "Missing completed reference")
    result = json_object(result_path)
    data = result.get("data", {})
    require(result.get("operation") == "native.regmap-two-prelock" and
            result.get("status") == "passed" and result.get("exit_code") == 0 and
            data.get("mode") == "reference" and data.get("matched") is True and
            data.get("order", "ab") == order and data.get("identities") == identities and
            data.get("guest_timer") == timer and data.get("host_placement") == placement and
            data.get("guest_housekeeping") == housekeeping,
            "Reference has not passed for this direction and registration")
    witness = checked_capture(directory, plan, order, timer, placement, housekeeping)
    require(witness == json_object(witness_path) and data.get("witness_sha256") == digest(witness_path),
            "Reference no longer agrees with its sealed capture")
    return witness, {"directory": str(directory), "boot_id": witness["boot_id"],
                     "result_sha256": digest(result_path), "witness_sha256": digest(witness_path)}


def run(task, out, envelope):
    inputs = task["inputs"]
    order, timer, placement, housekeeping = "ba", None, "pinned-vcpus", "cpu2-3"
    identities = dict(IMAGE_HASHES)
    mode = "cold" if inputs.get("reference") else "reference"
    cmdline = "console=ttyS0 panic=-1 loglevel=4 " + HOUSEKEEPING_ARGS
    data = {"mode": mode, "order": order, "guest_started": False, "matched": False,
            "identities": identities, "host_placement": placement, "guest_housekeeping": housekeeping}
    envelope["data"] = data
    paths = registered_files(Path(inputs["bundle"]), Path(inputs["disk"]))
    require(all("," not in str(p) for p in [out, paths["disk"]]), "Comma in QEMU disk or output path")
    reference, admitted = None, None
    if mode == "cold":
        reference, admitted = accepted_reference(Path(inputs["reference"]), paths["plan"], order,
                                                 identities, timer, placement, housekeeping)

    # A separate evidence disk gives every invocation its own guest-written seal.
    evidence = out / "evidence.ext4"
    with evidence.open("xb") as stream:
        stream.truncate(24 << 20)
    with (out / "format.log").open("xb") as log:
        subprocess.run(["/usr/sbin/mkfs.ext4", "-q", "-F", str(evidence)],
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    require("," not in str(out), "QEMU output directory must not contain a comma")
    argv = ["qemu-system-x86_64", "-accel", "kvm", "-cpu", "host", "-smp", "4", "-m", "4096",
            "-no-reboot", "-nodefaults", "-display", "none", "-monitor", "none",
            "-serial", "file:" + str(out / "serial.log"), "-kernel", str(paths["kernel"]),
            "-initrd", str(paths["initrd"]), "-append", cmdline,
            "-drive", f"file={paths['disk']},format=qcow2,if=virtio,readonly=on",
            "-drive", f"file={evidence},format=raw,if=virtio"]
    argv += ["-S", "-qmp", "stdio"]
    prelaunch = {"utc": now(), "mode": mode, "order": order, "admitted_reference": admitted, "argv": argv,
                 "build_id": BUILD_ID, "identities": identities,
                 "files": {name: str(path) for name, path in paths.items()}}
    save(out / "prelaunch.json", prelaunch)
    envelope["backend"] = {"name": "MAccConc", "command": argv}
    with (out / "qemu.log").open("xb") as log:
        try:
            from .prelock_vcpu_placement import run_pinned
            code = run_pinned(argv, log, out, timeout=180)
        except subprocess.TimeoutExpired:
            code = 124
    serial = out / "serial.log"
    data["guest_started"] = serial.is_file() and bool(re.search(
        r"^BOOT [0-9a-f-]{36}$", serial.read_text(errors="replace"), re.MULTILINE))
    save(out / "exit.json", {"utc": now(), "exit": code, "guest_started": data["guest_started"]})
    raw = out / "raw"
    raw.mkdir()
    with (out / "extract.log").open("xb") as log:
        subprocess.run(["/usr/sbin/debugfs", "-R", "rdump / .", str(evidence)],
                       cwd=raw, stdout=log, stderr=subprocess.STDOUT, check=True)
    require(code == 0 and data["guest_started"], f"Guest did not finish normally (QEMU {code})")
    witness = checked_capture(out, paths["plan"], order, timer, placement, housekeeping)
    if reference:
        require(witness["boot_id"] != reference["boot_id"], "Cold confirmation reused reference boot")
        for key in ("plan_sha256", "target_stack", "kernel_build_id", "update_sequence", "final_read"):
            require(witness[key] == reference[key], f"Cold confirmation differs: {key}")
    witness_path = out / "witness.json"
    save(witness_path, witness)
    data.update(matched=True, boot_id=witness["boot_id"], witness_sha256=digest(witness_path),
                reference=admitted, tids=witness["tids"], call_lines=witness["call_lines"],
                update_sequence=witness["update_sequence"], final_read=witness["final_read"])
