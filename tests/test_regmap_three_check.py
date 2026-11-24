import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kconc.regmap_three_check import case_reports, parse, replay, write_html


def sample(prop, variant, order="ABC", tid_base=101):
    if variant == "fault" and prop == "mutex":
        shape = [(r,"ENTER") for r in order] + [(r,k) for r in order for k in ("READ","WRITE","EXIT")]
    elif variant == "fault" and prop == "update":
        shape = [(r,k) for r in order for k in ("ENTER","READ")] + [(r,k) for r in order for k in ("WRITE","EXIT")]
    else:
        shape = [(r,k) for r in order for k in ("ENTER","READ","WRITE","EXIT")]
    values = {}
    state = 0
    out = [f"TRI_BEGIN property={prop} variant={variant} order={order} initial=0"]
    for seq,(role, kind) in enumerate(shape,1):
        offset = "ABC".index(role)
        value = 0
        if kind == "READ":
            values[role] = value = state
        if kind == "WRITE":
            state = value = values[role] | 1 << offset
        out.append(f"TRI_EVENT seq={seq} role={role} tid={tid_base+offset} kind={kind} reg=0 value={value}")
    out.extend(f"TRI_THREAD role={r} tid={tid_base+i} rc=0" for i,r in enumerate("ABC"))
    out.extend([f"TRI_READBACK tid=16 reg=0 value={state} rc=0",f"TRI_END final={state} ok=1","TRI_CLEAN"])
    return "\n".join(out)


class ThreeRoleProperties(unittest.TestCase):
    def test_serial_update_and_shared_lock(self):
        for prop in ("update","mutex"):
            for variant in ("normal","fixed"):
                for order in ("ABC","ACB"):
                    r = parse(sample(prop,variant,order),prop,variant,order)
                    self.assertTrue(r["complete"] and r["matched"])
                    self.assertFalse(r["violation"])
                    self.assertEqual((r["final"],r["mutex"]["peak"]),(7,1))

    def test_update_with_overwrites_and_intervals(self):
        for order,final in (("ABC",4),("ACB",2)):
            r = parse(sample("update","fault",order),"update","fault",order)
            self.assertTrue(r["eligible_witness"])
            self.assertEqual(r["final"],final)
            self.assertEqual(r["mutex"]["peak"],3)
            self.assertEqual([(e["lost_role"],e["writer"]) for e in r["update"]["overwritten"]], list(zip(order,order[1:])))

    def test_mutex_fails_with_all_bits_preserved(self):
        r = parse(sample("mutex","fault"),"mutex","fault","ABC")
        self.assertEqual(r["final"],7)
        self.assertTrue(r["eligible_witness"])
        self.assertFalse(r["update"]["violated"])
        self.assertEqual([x["roles"] for x in r["mutex"]["overlapping"]],[["A","B"],["A","C"],["B","C"]])

    def test_valid_off_candidate_keeps_property_without_a_witness_hit(self):
        text = sample("mutex","fault","ACB").replace("order=ACB","order=ABC")
        r = parse(text,"mutex","fault","ABC")
        self.assertTrue(r["complete"] and r["violation"])
        self.assertFalse(r["matched"] or r["eligible_witness"])

    def test_bad_observation_cannot_give_a_valid_verdict(self):
        text = sample("mutex","fault")
        for changed in ("",text+"\nTRI_CLEAN",text.removesuffix("TRI_CLEAN"),
                        text.replace("seq=3 ","seq=2 "), text.replace("tid=103","tid=102"),
                        text.replace("tid=16 ","tid=103 "), text.replace("kind=READ reg=0 value=1","kind=READ reg=0 value=0"),
                        text.replace("role=C tid=103 rc=0","role=B tid=102 rc=0"),
                        text.replace("value=7 rc=0","value=6 rc=0"),
                        text.replace("TRI_END final=7","TRI_END final=6"),
                        text.replace("kind=WRITE reg=0 value=7","kind=WRITE reg=0 value=5"),
                        text.replace("TRI_EVENT seq=7 ", "untrusted: TRI_EVENT seq=7 ")):
            with self.subTest(changed=changed[:45]):
                r = parse(changed,"mutex","fault","ABC")
                self.assertFalse(r["complete"] or r["eligible_witness"])
                self.assertIsNone(r["violation"])

    def test_replay_requires_identity_and_role_path_not_reused_tids(self):
        a = parse(sample("mutex","normal"),"mutex","normal","ABC")
        b = parse(sample("mutex","normal",tid_base=201),"mutex","normal","ABC")
        self.assertTrue(replay(a,b,"frozen","frozen")["matched"])
        for prior,current in (("",""),("frozen","other")):
            self.assertFalse(replay(a,b,prior,current)["matched"])
        reverse=parse(sample("mutex","normal","ACB"),"mutex","normal","ACB")
        self.assertEqual(a["final"],reverse["final"])
        self.assertFalse(replay(a,reverse,"frozen","frozen")["matched"])

    def test_report_keeps_text_safe_and_preserves_existing_witness(self):
        a = parse(sample("update","fault"),"update","fault","ABC")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/"witness.html"
            write_html(p,a,title="<note>")
            html = p.read_text(encoding="utf-8")
            self.assertIn("&lt;note&gt;",html)
            self.assertIn("覆盖先前更新的写入",html)
            self.assertIn("临界区重叠",html)
            with self.assertRaises(FileExistsError):
                write_html(p,a)

    def test_case_sections_preserve_absolute_serial_locations_and_failures(self):
        prefix = ["booting", "CASE_BEGIN update normal ABC", "module name and fingerprint"]
        first = sample("update", "normal").splitlines()
        second = sample("mutex", "fault", "ACB").splitlines()
        serial = prefix + first + ["CASE_BEGIN mutex fault ACB", "ftrace event"] + second + ["CASE_END"]
        cases, errors = case_reports(serial)
        self.assertEqual(errors, [])
        self.assertEqual(len(cases), 2)
        self.assertTrue(cases[1]["eligible_witness"])
        self.assertFalse(cases[0]["complete"])
        self.assertIsNone(cases[0]["end_line"])
        first_event = cases[1]["events"][0]
        self.assertEqual(serial[first_event["line"] - 1], second[1])
        self.assertEqual(cases[1]["end_line"], len(serial))

    def test_case_boundaries_and_case_header_cannot_be_forged(self):
        header, logs = "CASE_BEGIN mutex fault ABC", sample("mutex", "fault")
        malformed = ["CASE_END\n" + header, "CASE_BEGIN mutex fault BCA", header + "\n" + logs,
                     header + "\n" + logs + "\nCASE_END rc=1", header.replace("fault", "normal") + "\n" + logs + "\nCASE_END",
                     header + "\n" + logs + "\nCASE_END\nTRI_CLEAN"]
        for text in malformed:
            with self.subTest(text=text[:40]):
                cases, errors = case_reports(text)
                self.assertTrue(errors or any(not case["complete"] for case in cases))

    def test_guest_colored_timestamps_preserve_content_and_source_line(self):
        prefix = "\x1b[32m[    1.697889] \x1b[0m"
        lines = [prefix + line for line in sample("update", "normal").splitlines()]
        cases, errors = case_reports(["CASE_BEGIN update normal ABC", *lines, "CASE_END"])
        self.assertEqual(errors, [])
        self.assertTrue(cases[0]["complete"] and cases[0]["matched"])
        self.assertEqual(cases[0]["events"][0]["line"], 3)
        lines[1] = "\x1b[2J"+lines[1]
        self.assertFalse(parse(lines, "update", "normal", "ABC")["complete"])

    def test_developer_cli_selects_all_matching_cases_without_overwriting_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            serial = directory / "serial.log"
            report_dir = directory / "witnesses"
            serial.write_text("CASE_BEGIN update fixed ABC\n"+sample("update", "fixed")+"\nCASE_END\n"
                              "CASE_BEGIN mutex fault ACB\n"+sample("mutex", "fault", "ACB")+"\nCASE_END\n",
                              encoding="utf-8")
            checker = Path(__file__).resolve().parents[1] / "src" / "kconc" / "regmap_three_check.py"
            cmd = [sys.executable, "-B", str(checker), str(serial)]
            def run(*args):
                return subprocess.run(cmd + list(args), capture_output=True, text=True)
            both = run()
            self.assertEqual(both.returncode, 0, both.stderr)
            self.assertEqual(json.loads(both.stdout)["selected"], 2)
            flags = ("--variant", "fault", "--order", "ACB", "--html-dir", str(report_dir))
            selected = run(*flags)
            self.assertEqual(selected.returncode, 0, selected.stderr)
            report = json.loads(selected.stdout)
            self.assertEqual(report["sha256"], hashlib.sha256(serial.read_bytes()).hexdigest())
            self.assertTrue(report["cases"][0]["eligible_witness"])
            self.assertEqual([p.name for p in report_dir.iterdir()], ["002-mutex-fault-ACB.html"])
            self.assertEqual(run(*flags).returncode, 2)
            self.assertEqual(run("--property", "mutex", "--variant", "normal").returncode, 1)


if __name__ == "__main__":
    unittest.main()
