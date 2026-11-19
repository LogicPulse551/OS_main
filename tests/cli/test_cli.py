"""Offline command boundaries; fixtures never execute a VM or a backend."""
from contextlib import nullcontext, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from kconc import cli


class CliTests(unittest.TestCase):
    def setUp(self):
        # Portable across clones; evidence never goes in the delivery repository.
        self.directory = tempfile.TemporaryDirectory(prefix="kconc-cli-")
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        identity = patch.object(cli, "implementation", return_value={"commit": "offline-fixture", "files": {}})
        identity.start()
        self.addCleanup(identity.stop)

    def task(self, operation="k03.view"):
        task = {"schema_version": 1, "operation": operation,
                "runtime": {"lab_dir": str(self.base / "runtime with spaces"), "ssh_port": 2224}, "inputs": {}}
        if operation == "k03.view":
            task["inputs"] = {"trace": str(self.base / "trace with spaces ; literal.json")}
        if operation == "env.check":
            task["runtime"].update(build_lab=str(self.base / "build lab"),
                                   kernel_build=str(self.base / "kernel build"),
                                   probe_guest_build="/home/lab/k02/build")
        return task

    @staticmethod
    def view_result(**updates):
        value = {"passed": True, "action": "view", "mode": "archived-trace-view-only",
                 "frame_bytes": 24, "frame_sha256": "a" * 64,
                 "trace": "archived fixture", "ui_verified": False}
        value.update(updates)
        return value

    def simulate(self, task, payload, code=0):
        """Exercise the live adapter with a fake process, not a fake verdict."""
        def execute(command, env, out, timeout, envelope):
            _, target = cli.backend_command(task, out)
            envelope["backend"] = {"command": command, "exit_code": code}
            (out / "backend.stdout.json").write_bytes(b"retained stdout\n")
            (out / "backend.stderr.txt").write_bytes(b"retained stderr\n")
            if payload is not None:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps(payload), encoding="utf-8")
            return code

        out = self.base / "new run"
        with patch.object(cli, "runtime_lock", return_value=nullcontext()), \
                patch.object(cli, "require_vsock_port"), \
                patch.object(cli, "execute_process", side_effect=execute) as process:
            value = cli.run_task(inline=task, output=out)
        self.assertEqual(process.call_count, 1)
        self.assertEqual(json.loads((out / "result.json").read_text(encoding="utf-8")), value)
        return value, out

    def test_repository_and_ancestor_outputs_are_rejected_before_backend(self):
        with patch.object(cli, "run_live") as backend:
            for target in (REPO / "test-evidence-must-not-exist", REPO, REPO.parent):
                with self.subTest(target=target):
                    value = cli.run_task(inline=self.task(), output=target)
                    self.assertEqual((value["status"], value["exit_code"]), ("invalid", 2))
                    self.assertEqual(value["error"]["code"], "invalid_output")
            backend.assert_not_called()
        self.assertFalse((REPO / "test-evidence-must-not-exist").exists())

    def test_existing_output_and_result_are_never_overwritten(self):
        out = self.base / "already recorded"
        out.mkdir()
        original = b'{"original evidence":true}\n'
        (out / "result.json").write_bytes(original)
        with patch.object(cli, "run_live") as backend:
            value = cli.run_task(inline=self.task(), output=out)
            backend.assert_not_called()
        self.assertEqual(value["error"]["code"], "output_exists")
        self.assertEqual((out / "result.json").read_bytes(), original)
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["result.json"])

    def test_unsupported_command_has_explicit_failure_and_no_backend(self):
        out = self.base / "unsupported"
        with patch.object(cli, "run_live") as backend:
            value = cli.run_task(inline={"schema_version": 1, "operation": "optimize"}, output=out)
            backend.assert_not_called()
        self.assertEqual((value["status"], value["exit_code"]), ("unsupported", 3))
        self.assertEqual(value["error"]["code"], "unsupported_operation")
        self.assertIsNone(value["backend"])
        self.assertEqual(json.loads((out / "result.json").read_text(encoding="utf-8")), value)

    def test_malformed_manifest_retains_structured_failure(self):
        source = self.base / "broken task.json"
        source.write_text('{"schema_version":', encoding="utf-8")
        out = self.base / "invalid"
        with patch.object(cli, "run_live") as backend:
            value = cli.run_task(manifest=source, output=out)
            backend.assert_not_called()
        self.assertEqual((value["status"], value["exit_code"]), ("invalid", 2))
        self.assertTrue(value["error"]["code"])
        self.assertIsNotNone(value["finished_utc"])
        self.assertEqual(json.loads((out / "result.json").read_text(encoding="utf-8")), value)

    def test_backend_nonzero_cannot_become_success(self):
        value, out = self.simulate(self.task(), {"passed": False, "action": "view",
                                               "error": {"type": "Fixture", "message": "failed"}}, code=7)
        self.assertEqual((value["status"], value["exit_code"]), ("failed", 1))
        self.assertEqual(value["backend"]["exit_code"], 7)
        self.assertFalse(value["data"]["backend_report"]["reported_passed"])
        self.assertEqual((out / "backend.stderr.txt").read_bytes(), b"retained stderr\n")

    def test_success_claim_with_nonzero_backend_exit_is_rejected(self):
        value, _ = self.simulate(self.task(), self.view_result(), code=7)
        self.assertEqual(value["status"], "failed")
        self.assertEqual(value["backend"]["exit_code"], 7)
        self.assertEqual(value["error"]["code"], "inconsistent_result")

    def test_zero_backend_exit_without_result_is_rejected(self):
        value, _ = self.simulate(self.task(), None)
        self.assertEqual((value["status"], value["exit_code"]), ("failed", 1))
        self.assertIsNotNone(value["error"])

    def test_nonzero_backend_exit_without_result_preserves_failure_cause(self):
        value, _ = self.simulate(self.task(), None, code=9)
        self.assertEqual(value["status"], "failed")
        self.assertEqual(value["error"]["code"], "backend_failed")
        self.assertEqual(value["backend"]["exit_code"], 9)

    def test_contradictory_backend_claim_is_rejected(self):
        value, _ = self.simulate(self.task(), self.view_result(ui_verified=True))
        self.assertEqual(value["status"], "failed")
        self.assertEqual(value["error"]["code"], "inconsistent_result")

    def test_success_for_a_different_backend_operation_is_rejected(self):
        # A successful build does not establish that the requested view ran.
        value, _ = self.simulate(self.task(), {"passed": True, "action": "build",
                                               "exit_code": 0, "guest_build": "/home/lab/k03/build"})
        self.assertEqual((value["status"], value["exit_code"]), ("failed", 1))
        self.assertIsNotNone(value["error"])

    def test_transport_only_does_not_establish_full_environment_check(self):
        value, _ = self.simulate(self.task("env.check"), {"task": "K02", "mode": "transport-only",
                                "passed": True, "checks": {"transport": True}, "errors": [], "exit_code": 0})
        self.assertEqual((value["status"], value["exit_code"]), ("failed", 1))
        self.assertIsNotNone(value["error"])

    def test_valid_view_preserves_its_limited_scope(self):
        value, _ = self.simulate(self.task(), self.view_result())
        self.assertEqual((value["status"], value["exit_code"]), ("passed", 0))
        report = value["data"]["backend_report"]
        self.assertEqual(report["kind"], "maccconc.k03.view")
        self.assertFalse(report["summary"]["ui_verified"])
        self.assertFalse(report["revalidated"])

    def test_historical_failure_can_be_read_without_becoming_a_pass(self):
        source = self.base / "old failed replay.json"
        source.write_text(json.dumps({"passed": False, "action": "replay",
                                      "error": {"type": "Fixture", "message": "recorded failure"}}), encoding="utf-8")
        with patch.object(cli, "run_live") as backend:
            value = cli.run_task(inline={"schema_version": 1, "operation": "result.read",
                                         "inputs": {"result": str(source)}})
            backend.assert_not_called()
        self.assertEqual((value["status"], value["exit_code"]), ("read", 0))
        self.assertFalse(value["data"]["reported_passed"])
        self.assertFalse(value["data"]["revalidated"])
        self.assertEqual(value["data"]["source"]["sha256"], hashlib.sha256(source.read_bytes()).hexdigest())

    def test_stopped_status_is_observation_not_execution_readiness(self):
        value, _ = self.simulate(self.task("env.status"), {"state": "stopped"})
        self.assertEqual((value["status"], value["exit_code"]), ("passed", 0))
        self.assertFalse(value["data"]["vm_running"])
        self.assertFalse(value["data"]["execution_readiness_verified"])

    def test_live_environment_does_not_inherit_unrelated_lab_overrides(self):
        task = self.task()
        seen = {}

        def execute(command, env, out, timeout, envelope):
            seen.update(env)
            envelope["backend"] = {"exit_code": 0}
            target = out / "backend/result.json"
            target.parent.mkdir()
            target.write_text(json.dumps(self.view_result()), encoding="utf-8")
            return 0

        with patch.object(cli, "runtime_lock", return_value=nullcontext()), \
                patch.object(cli, "execute_process", side_effect=execute), \
                patch.dict(cli.os.environ, {"LAB_DIR": "wrong", "LAB_SSH_PORT": "22", "LAB_QMP_SOCKET": "wrong"}):
            value = cli.run_task(inline=task, output=self.base / "environment")
        self.assertEqual(value["status"], "passed")
        self.assertEqual(seen["LAB_DIR"], task["runtime"]["lab_dir"])
        self.assertEqual(seen["LAB_SSH_PORT"], "2224")
        self.assertNotIn("LAB_QMP_SOCKET", seen)

    def test_argv_spaces_logs_and_exit_code_survive_without_a_shell(self):
        out = self.base / "space in output"
        out.mkdir()
        task = self.task()
        command, _ = cli.backend_command(task, out)
        stdout_bytes = b"raw stdout\r\n\x00"
        stderr_bytes = b"raw stderr\r\n"
        observed = {}

        class Child:
            pid, returncode = 43210, 7

            def wait(self, timeout):
                observed["timeout"] = timeout
                return self.returncode

        def launch(argv, **kwargs):
            observed.update(argv=argv, kwargs=kwargs)
            kwargs["stdout"].write(stdout_bytes)
            kwargs["stderr"].write(stderr_bytes)
            return Child()

        envelope = {"data": {}}
        with patch.object(cli.subprocess, "Popen", side_effect=launch):
            code = cli.execute_process(command, {"EXPLICIT": "value"}, out, 11, envelope)
        self.assertEqual(code, 7)
        self.assertIsInstance(observed["argv"], list)
        self.assertEqual(observed["argv"][observed["argv"].index("--trace") + 1], task["inputs"]["trace"])
        self.assertEqual(observed["argv"][observed["argv"].index("--output") + 1], str(out / "backend"))
        self.assertFalse(observed["kwargs"].get("shell", False))
        self.assertEqual(observed["kwargs"]["env"], {"EXPLICIT": "value"})
        self.assertEqual(observed["timeout"], 11)
        self.assertEqual(envelope["backend"]["exit_code"], 7)
        for field, data in (("stdout", stdout_bytes), ("stderr", stderr_bytes)):
            self.assertEqual(Path(envelope["backend"][field]).read_bytes(), data)
            self.assertEqual(envelope["backend"][field + "_sha256"], hashlib.sha256(data).hexdigest())

    def test_argument_errors_are_structured_and_nonzero(self):
        output = io.StringIO()
        with redirect_stdout(output), patch.object(cli, "run_live") as backend:
            code = cli.main(["run", "task.json"])
            backend.assert_not_called()
        value = json.loads(output.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(value["status"], "invalid")
        self.assertEqual(value["error"]["code"], "invalid_arguments")

    def test_output_write_failure_still_returns_structured_failure(self):
        with patch.object(cli, "save", side_effect=OSError("injected disk failure")), \
                patch.object(cli, "run_live") as backend:
            value = cli.run_task(inline={"schema_version": 1, "operation": "optimize"},
                                 output=self.base / "disk failure")
            backend.assert_not_called()
        self.assertEqual((value["status"], value["exit_code"]), ("failed", 1))
        self.assertIsNotNone(value["error"])

    def test_error_after_spawn_cleans_up_child_and_marks_recovery(self):
        out = self.base / "post spawn failure"
        out.mkdir()

        class Child:
            pid, returncode = 43210, None

            def poll(self):
                return self.returncode

            def wait(self, timeout):
                self.returncode = -15
                return self.returncode

        real_save = cli.save

        def fail_after_spawn(path, value):
            if value.get("backend", {}).get("pid"):
                raise OSError("injected PID write failure")
            real_save(path, value)

        envelope = {"data": {}}
        with patch.object(cli.subprocess, "Popen", return_value=Child()), \
                patch.object(cli, "save", side_effect=fail_after_spawn), \
                patch.object(cli.os, "killpg", create=True) as kill:
            with self.assertRaises((OSError, cli.OperationError)):
                cli.execute_process(["offline fixture"], {}, out, 1, envelope)
        self.assertTrue(kill.called, "A started backend must be stopped before releasing its runtime lock")
        self.assertTrue(envelope["data"].get("recovery_required"))
        self.assertIsNotNone(envelope["backend"]["exit_code"])

    def test_timeout_exit_race_retains_timeout_and_recovery_flag(self):
        out = self.base / "timeout race"
        out.mkdir()

        class Child:
            pid, returncode, waits = 43210, None, 0

            def poll(self):
                return self.returncode

            def wait(self, timeout):
                self.waits += 1
                if self.waits == 1:
                    raise subprocess.TimeoutExpired(["offline fixture"], timeout)
                self.returncode = 0
                return self.returncode

        envelope = {"data": {}}
        with patch.object(cli.subprocess, "Popen", return_value=Child()), \
                patch.object(cli.os, "killpg", side_effect=ProcessLookupError("process exited before signal"), create=True):
            with self.assertRaises(cli.OperationError) as caught:
                cli.execute_process(["offline fixture"], {}, out, 1, envelope)
        self.assertEqual(caught.exception.code, "backend_timeout")
        self.assertTrue(envelope["data"].get("recovery_required"))
        self.assertTrue(envelope["backend"]["timed_out"])


if __name__ == "__main__":
    unittest.main()
