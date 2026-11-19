"""Small guest reports exercising the same entry point as the boot collector."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "c06-bma400-check.py"
SPEC = importlib.util.spec_from_file_location("c06_checker", SCRIPT)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

PARAMETERS = {"calls": 1, "samples": 1, "warmups": 0}
PARAMS = "kconc_bma400.calls=1 kconc_bma400.samples=1 kconc_bma400.warmups=0"
FIXTURE = "/sys/kernel/debug/kconc-bma400/results"
OBSERVER = "/sys/kernel/debug/kconc-c06-observer/results"


def expected_bytes():
    on_wire = {8: "848688", 16: "848586"}
    converted = {8: "123456789abc", 16: "34127856bc9a"}
    callbacks = {8: "regmap_parse_inplace_noop", 16: "regmap_parse_16_be_inplace"}
    checks = []
    for bits in (8, 16):
        for fail, rc in enumerate((0, -5, -110, -121)):
            sent = fail or 3
            prefix = (fail - 1) * 4
            data = converted[bits] if not fail else "123456789abc"[:prefix].ljust(12, "c")
            checks.append(dict(bits=bits, fail_at=fail, rc=rc, transfers=sent,
                               wire=on_wire[bits][:2 * sent].ljust(6, "0"),
                               lengths=("02" * sent).ljust(6, "0"), data=data,
                               converter=callbacks[bits], result=0))
    return checks


def sync_raw(col):
    for key, name in (("fixture", FIXTURE), ("observer", OBSERVER)):
        value = col[key]
        col["debugfs"][name] = {"exists": value is not None,
                                "text": None if value is None else json.dumps(value) + "\n"}


def boot(mode="check"):
    widths = {"off": (), "bench": (8,), "observe": (8,)}.get(mode, (8, 16))
    kind = {"off": "absent", "bench": "single_bulk", "observe": "single_bulk"}.get(mode, "checks")
    expected, observed = [], []
    for width in widths:
        private = width == 8 and mode not in ("observe", "foreign")
        starts = 9 if kind == "checks" else 3
        visible = mode == "foreign"
        expected.append(dict(bits=width, raw_starts=starts, path="private" if private else "public",
                             target_node="present" if visible else "absent"))
        observed.append(dict(width=width, hidden=int(not visible), raw_starts=starts,
                             private_hits=starts if private else 0, public_hits=0 if private else starts,
                             unresolved=0, bulk_success=1, control_ready=1, overlap=1, control_ok=1,
                             control_joined=1, control_bus_reads=1, control_live_visible=1,
                             target_live_visible=int(visible), target_removed=1, control_removed=1, reader_rc=0))
    plan = dict(command_parameters=PARAMETERS.copy(), expected_checks=expected_bytes(),
                slots=[dict(id=mode, mode=mode, fixture=kind, off_mode_omitted=mode == "off", maps=expected)])
    fixture = None
    if kind != "absent":
        fixture = dict(schema=1, mode=mode, **PARAMETERS,
                       checks=copy.deepcopy(plan["expected_checks"]) if kind == "checks" else [],
                       rows=[] if kind == "checks" else [dict(sample=0, warmup=0, cycles=1, bus_reads=3, result=0)])
    col = dict(schema=1, online="0-3", cmdline=PARAMS + ("" if mode == "off" else " kconc_bma400.mode=" + mode),
               debugfs={}, fixture=fixture, observer=dict(schema=1, errors=0, maps=observed),
               final_regmap_entries=[], dmesg="systemd[1]: (This warning is only shown for the first unit using IP firewalling.)")
    sync_raw(col)
    return plan, col


class TestBma400Checker(unittest.TestCase):
    def test_clean_guest_modes(self):
        for mode in ("off", "check", "bench", "foreign", "observe"):
            with self.subTest(mode=mode):
                plan, col = boot(mode)
                verdict = CHECKER.verify_slot(plan, mode, col)
                self.assertTrue(verdict["passed"], verdict["violations"])

    def test_normal_conversion_and_failed_prefix(self):
        for width, fail, bad in ((8, 0, "34127856bc9a"), (16, 0, "123456789abc"),
                                 (16, 2, "3412cccccccc"), (8, 3, "123456789abc")):
            with self.subTest(width=width, fail=fail):
                plan, col = boot()
                row = next(c for c in col["fixture"]["checks"] if c["bits"] == width and c["fail_at"] == fail)
                row["data"] = bad
                sync_raw(col)
                verdict = CHECKER.verify_slot(plan, "check", col)
                self.assertFalse(verdict["passed"])
                self.assertTrue(any(".data" in issue for issue in verdict["violations"]))

    def test_mixed_private_public_counts(self):
        plan, col = boot()
        col["observer"]["maps"][0].update(private_hits=8, public_hits=1)
        sync_raw(col)
        self.assertFalse(CHECKER.verify_slot(plan, "check", col)["passed"])

    def test_observer_source_differs_from_collector_copy(self):
        plan, col = boot()
        col["debugfs"][OBSERVER]["text"] = '{"schema":1,"errors":0,"maps":[]}\n'
        self.assertFalse(CHECKER.verify_slot(plan, "check", col)["passed"])

    def test_duplicate_control_arguments(self):
        for mode, extra in (("check", " kconc_bma400.mode=check"), ("off", " kconc_bma400.mode=off"),
                            ("bench", " kconc_bma400.warmups=0")):
            with self.subTest(mode=mode):
                plan, col = boot(mode)
                col["cmdline"] += extra
                self.assertFalse(CHECKER.verify_slot(plan, mode, col)["passed"])

    def test_lifetime_and_observation_evidence(self):
        for field in ("overlap", "control_joined", "control_live_visible", "target_removed", "control_removed", "reader_rc"):
            with self.subTest(field=field):
                plan, col = boot("foreign")
                row = col["observer"]["maps"][1]
                row[field] = int(not row[field])
                sync_raw(col)
                self.assertFalse(CHECKER.verify_slot(plan, "foreign", col)["passed"])

    def test_guest_cannot_attest_host_shutdown(self):
        plan, col = boot("off")
        col["clean_stop"] = True
        del col["observer"]
        self.assertFalse(CHECKER.verify_slot(plan, "off", col)["passed"])
        _, clean = boot("off")
        verdict = CHECKER.verify_slot(plan, "off", clean)
        self.assertNotIn("clean_stop", verdict)

    def test_kernel_diagnostic_is_retained(self):
        plan, col = boot()
        col["dmesg"] += "\n[ 1.25] WARNING: CPU: 0 PID: 2 at observer.c"
        self.assertFalse(CHECKER.verify_slot(plan, "check", col)["passed"])


if __name__ == "__main__":
    unittest.main()
