"""Reuse K10 native control probes on the actual K11-patched K08 runner.

These compile real control functions with syscall/thread stubs, not a VM or a
schedule model. They test abort/order boundaries; real sampling remains separate.
"""
import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


k10 = load('k11_inherited_control_tests', REPO / 'tests/k10/test_native_control.py')
a = load('k11_sampler_analysis', REPO / 'adapters/maccconc/k11_analysis.py')
PATCH = REPO / 'adapters/maccconc/k11-sampler-control.patch'
SCRIPT = REPO / 'scripts/build-k11-guest.sh'


def source():
    before, accepted = k10.patch_images()
    actual = a.apply_file_patch(before, PATCH.read_text(), 'runner-common.h')
    if actual != accepted:
        raise AssertionError('K11 sampler control must reuse the accepted K10 runner exactly')
    return actual


class SamplerSourceTests(unittest.TestCase):
    def test_sampler_runner_equals_accepted_k10_implementation(self):
        self.assertIn('k10_wait_a_ready', source())

    def test_build_python_blocks_compile(self):
        blocks = re.findall(r"<<'PY'\n(.*?)\nPY\n", SCRIPT.read_text(), re.S)
        self.assertEqual(len(blocks), 4)
        for index, block in enumerate(blocks):
            compile(block, f'build-k11-guest block {index}', 'exec')

    @unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('bash'), 'Linux bash required')
    def test_build_shell_syntax(self):
        result = subprocess.run(['bash', '-n', str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


@unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('g++'), 'Linux g++ required')
class SamplerBehaviorTests(k10.NativeControlBehaviorTests):
    @classmethod
    def setUpClass(cls):
        text = source()
        structure = text[text.index('struct K03Control {'):text.index('};', text.index('struct K03Control {')) + 2]
        state = structure + '\nstatic K03Control shared_control{};\nstatic K03Control *k03_control=&shared_control;\n'
        prelude = k10.PRELUDE.replace('static long fake_syscall(long number) {',
            'static void observe_gettid();\nstatic long fake_syscall(long number) {').replace(
            'log_events.push_back("gettid"); return main_slot ? 101 : 202;',
            'observe_gettid(); log_events.push_back("gettid"); return main_slot ? 101 : 202;')
        callback = r'''
static void observe_gettid() {
  if(main_slot) require(k03_control->k10_a_ready==0,"A published ready before gettid completed");
}
static void k08_run_slot(unsigned int slot) {
  if(slot==0) require(__atomic_load_n(&k03_control->k10_a_ready,__ATOMIC_ACQUIRE)==1,"A callback preceded readiness");
  require(kcov_insts[slot].cover[0]==0,"measurement counter was not reset");
  ++callback_count[slot]; log_events.push_back("callback"+std::to_string(slot)); kcov_insts[slot].cover[0]=1;
}
'''
        functions = '\n'.join(k10.function(text, name) for name in (
            'static bool k10_wait_a_ready(', 'static void *rtic_thread_fn(', 'static void run_testcase_in_child('))
        ready_failure = r'''
    } else if(mode=="ready-failure") {
      k03_control->k10_a_ready=0; bool inner=true; int status=-1;
      try { rtic_thread_fn(&inner); } catch(const ChildExit &e) { status=e.status; }
      require(status==125,"readiness exhaustion must terminate the child");
      require(k03_control->gate_called==0,"gate entered before readiness");
      require(callback_count[1]==0 && k03_control->b_done==0,"unready B ran a callback");
      require(k03_control->b_wake_called==0,"unready B claimed a completion wake");
      require(std::find(log_events.begin(),log_events.end(),"finish-barrier")==log_events.end(),"unready B entered finish barrier");
'''
        main = k10.MAIN.replace('    } else if(mode=="slot-a" || mode=="reset-ready") {',
            ready_failure + '    } else if(mode=="slot-a" || mode=="reset-ready") {')
        cls.temp = tempfile.TemporaryDirectory(prefix='k11-sampler-control-')
        root = Path(cls.temp.name)
        code = root / 'test.cpp'
        code.write_text(prelude + state + callback + functions + main)
        cls.binary = root / 'test-sampler-control'
        result = subprocess.run(['g++', '-std=gnu++23', '-O2', '-Wall', str(code), '-o', str(cls.binary)], capture_output=True, text=True)
        if result.returncode:
            cls.temp.cleanup()
            raise AssertionError(result.stderr)

    def test_readiness_exhaustion_never_enters_gate_or_callback(self):
        result = subprocess.run([str(self.binary), 'ready-failure'], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
