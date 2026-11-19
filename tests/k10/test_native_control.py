"""Exercise the actual patched runner functions without KCOV, a VM or threads.

The adapter carries full context for the accepted runner. Its preimage is
checked against the fixed K09 source hash, then its real postimage functions
are compiled with syscall/thread stubs. The stubs observe order and failure
boundaries; they do not model kernel scheduling or prove replay stability.
"""
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
PATCH = REPO / 'adapters/maccconc/k10-control.patch'
SCRIPT = REPO / 'scripts/build-k10-guest.sh'
ACCEPTED_RUNNER = 'e99df9bfa3295b9349750df465792867728f3272d1761865447f4ca126298c56'


def patch_images():
    before, after = [], []
    hunks = 0
    for line in PATCH.read_text(encoding='utf-8').splitlines(keepends=True):
        if line.startswith(('--- ', '+++ ')):
            continue
        if line.startswith('@@ '):
            hunks += 1
            continue
        if line.startswith((' ', '-')):
            before.append(line[1:])
        if line.startswith((' ', '+')):
            after.append(line[1:])
    if hunks != 1:
        raise AssertionError('The test requires the complete accepted runner context')
    before, after = ''.join(before), ''.join(after)
    if hashlib.sha256(before.encode()).hexdigest() != ACCEPTED_RUNNER:
        raise AssertionError('Patch no longer binds the accepted K09 runner source')
    return before, after


def function(source, signature):
    start = source.index(signature)
    left = source.index('{', start)
    depth = 0
    for index in range(left, len(source)):
        if source[index] == '{':
            depth += 1
        elif source[index] == '}':
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError('Unclosed runner function')


PRELUDE = r'''
#include <pthread.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>
#define K03_EVIDENCE 1
#define KCOV_ENABLE 1
#define KCOV_TRACE_MEMORY_ACCESS 3
#define KCOV_SPINWAIT_DI_FLAG 4
#define KCOV_WAKE_DI_FLAG 5
#define KCOV_RESET_DI_FLAGS 6
struct ChildExit { int status; };
static std::vector<std::string> log_events;
static bool main_slot=false, gate_fail=false;
static int callback_count[2]={0,0};
static int fork_result=0;
static unsigned long coverage[2][2]={{0,0},{0,0}};
struct StubKcov { int fd; unsigned long *cover; unsigned long cover_n; };
static StubKcov instances[2]={{10,coverage[0],0},{11,coverage[1],0}};
static StubKcov *kcov_insts=instances;
static pthread_barrier_t rtic_init_barrier,rtic_finish_barrier;
static bool k03_enabled=true;
static const char *k03_child_stdout_path="stub-stdout";
static const char *k03_child_stderr_path="stub-stderr";
static void require(bool condition,const char *message) {
  if (!condition) throw std::runtime_error(message);
}
static void pin_to(int cpu) { log_events.push_back("pin"+std::to_string(cpu)); }
static int fake_ioctl(int fd,int command,unsigned long arg) {
  if (command==KCOV_ENABLE) log_events.push_back("enable"+std::to_string(fd-10));
  if (command==KCOV_SPINWAIT_DI_FLAG) {
    log_events.push_back("gate");
    if (gate_fail) { errno=ETIMEDOUT; return -1; }
  }
  if (command==KCOV_WAKE_DI_FLAG) log_events.push_back("wake"+std::to_string(arg));
  if (command==KCOV_RESET_DI_FLAGS) log_events.push_back("reset");
  return 0;
}
static int fake_barrier_wait(pthread_barrier_t *b) {
  log_events.push_back(b==&rtic_init_barrier ? "init-barrier" : "finish-barrier");
  return 0;
}
static int fake_barrier_init(pthread_barrier_t *,const pthread_barrierattr_t *,unsigned) { return 0; }
static int fake_create(pthread_t *t,const pthread_attr_t *,void *(*)(void *),void *) { *t=1; return 0; }
static int fake_join(pthread_t,void **) { return 0; }
static pid_t fake_fork() { log_events.push_back("fork"); return fork_result; }
static pid_t fake_waitpid(pid_t child,int *status,int) { *status=0; return child; }
static long fake_syscall(long number) {
  require(number==SYS_gettid,"unexpected added syscall");
  log_events.push_back("gettid"); return main_slot ? 101 : 202;
}
static FILE *fake_freopen(const char *,const char *,FILE *stream) { return stream; }
static ssize_t fake_write(int,const void *,size_t count) { log_events.push_back("diagnostic"); return count; }
[[noreturn]] static void fake_exit(int status) { throw ChildExit{status}; }
[[noreturn]] static void fake_error(int,const char *) { throw std::runtime_error("unexpected native error"); }
static void test_setup() { log_events.push_back("setup"); }
static void test_end() { log_events.push_back("teardown"); }
#define ioctl fake_ioctl
#define pthread_barrier_wait fake_barrier_wait
#define pthread_barrier_init fake_barrier_init
#define pthread_create fake_create
#define pthread_join fake_join
#define fork fake_fork
#define waitpid fake_waitpid
#define syscall fake_syscall
#define freopen fake_freopen
#define write fake_write
#define exit fake_exit
#define _exit fake_exit
#define err fake_error
#define errx fake_error
#define SYSCHK(expression) ({ auto value=(expression); if(value<0) throw std::runtime_error("SYSCHK failed"); value; })
'''

MAIN = r'''
static size_t position(const char *event) {
  auto at=std::find(log_events.begin(),log_events.end(),event);
  require(at!=log_events.end(),event);
  return at-log_events.begin();
}
int main(int argc,char **argv) {
  try {
    require(argc==2,"one test mode required");
    std::string mode=argv[1];
    if(mode=="ready") {
      k03_control->k10_a_ready=0;
      require(!k10_wait_a_ready(0),"zero budget must expire");
      require(!k10_wait_a_ready(4),"finite wait without readiness must expire");
      __atomic_store_n(&k03_control->k10_a_ready,1U,__ATOMIC_RELEASE);
      require(k10_wait_a_ready(1),"ready flag must be observed");
    } else if(mode=="gate-failure" || mode=="success") {
      k03_control->k10_a_ready=1; gate_fail=mode=="gate-failure"; bool inner=true;
      int status=-1;
      try { rtic_thread_fn(&inner); }
      catch(const ChildExit &e) { status=e.status; }
      require(position("enable1")<position("init-barrier"),"B enable moved");
      require(position("init-barrier")<position("gate"),"B gate moved before barrier");
      require(k03_control->gate_called==1,"gate evidence missing");
      if(gate_fail) {
        require(status==125,"gate failure must terminate child");
        require(k03_control->gate_rc==-1 && k03_control->gate_errno==ETIMEDOUT,"gate evidence lost");
        require(callback_count[1]==0 && k03_control->b_done==0,"failed gate ran callback");
        require(k03_control->b_wake_called==0,"failed gate claimed completion wake");
        require(std::find(log_events.begin(),log_events.end(),"finish-barrier")==log_events.end(),"failed gate entered barrier");
      } else {
        require(status==-1 && callback_count[1]==1,"successful gate must execute exactly one original callback");
        require(k03_control->gate_rc==0 && k03_control->gate_errno==0,"successful gate evidence wrong");
        require(position("gate")<position("gettid") && position("gettid")<position("callback1"),"B syscall/callback order changed");
        require(k03_control->b_done==1 && k03_control->b_wake_called==1,"completion evidence missing");
      }
    } else if(mode=="slot-a" || mode=="reset-ready") {
      main_slot=true;k03_control->k10_a_ready=1;
      fork_result=mode=="reset-ready" ? 42 : 0;
      int status=-1;
      try { run_testcase_in_child(false,true); }
      catch(const ChildExit &e) { status=e.status; }
      if(mode=="reset-ready") {
        require(status==-1 && k03_control->k10_a_ready==0,"new attempt retained stale readiness");
        require(k03_control->waitpid_result==42,"parent completion missing");
        require(callback_count[0]==0,"parent ran child callback");
      } else {
        require(status==0 && callback_count[0]==1,"A failed to complete");
        require(position("init-barrier")<position("enable0"),"A barrier moved into traced syscall interval");
        require(position("enable0")<position("gettid") && position("gettid")<position("callback0"),"A syscall/callback order changed");
        require(k03_control->k10_a_ready==1 && k03_control->a_done==1,"A readiness or completion missing");
      }
    } else throw std::runtime_error("unknown mode");
    return 0;
  } catch(const std::exception &error) { std::fprintf(stderr,"%s\n",error.what()); return 1; }
}
'''


class NativeControlSourceTests(unittest.TestCase):
    def test_patch_binds_complete_accepted_runner(self):
        before, after = patch_images()
        self.assertNotEqual(before, after)

    def test_build_python_blocks_compile(self):
        blocks = re.findall(r"<<'PY'\n(.*?)\nPY\n", SCRIPT.read_text(encoding='utf-8'), re.S)
        self.assertEqual(len(blocks), 3)
        for index, block in enumerate(blocks):
            compile(block, f'build-k10-guest block {index}', 'exec')

    @unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('bash'), 'Linux bash needed for shell syntax validation')
    def test_build_shell_syntax(self):
        result = subprocess.run(['bash', '-n', str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


@unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('g++'), 'Linux g++ needed for native mocked control tests')
class NativeControlBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, source = patch_images()
        structure = source[source.index('struct K03Control {'):source.index('};', source.index('struct K03Control {')) + 2]
        state = structure + '\nstatic K03Control shared_control{};\nstatic K03Control *k03_control=&shared_control;\n'
        callback = r'''
static void k08_run_slot(unsigned int slot) {
  if(slot==0) require(__atomic_load_n(&k03_control->k10_a_ready,__ATOMIC_ACQUIRE)==1,"A callback preceded readiness");
  require(kcov_insts[slot].cover[0]==0,"measurement counter was not reset");
  ++callback_count[slot]; log_events.push_back("callback"+std::to_string(slot)); kcov_insts[slot].cover[0]=1;
}
'''
        functions = '\n'.join(function(source, name) for name in (
            'static bool k10_wait_a_ready(', 'static void *rtic_thread_fn(',
            'static void run_testcase_in_child('))
        cls.temp = tempfile.TemporaryDirectory(prefix='k10-native-control-')
        root = Path(cls.temp.name)
        code = root / 'test.cpp'
        code.write_text(PRELUDE + state + callback + functions + MAIN, encoding='utf-8')
        cls.binary = root / 'test-native-control'
        result = subprocess.run(['g++', '-std=gnu++23', '-O2', '-Wall', str(code), '-o', str(cls.binary)], capture_output=True, text=True)
        if result.returncode:
            cls.temp.cleanup()
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def check_mode(self, mode):
        result = subprocess.run([str(self.binary), mode], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ready_wait_is_bounded_and_observes_release(self):
        self.check_mode('ready')

    def test_gate_failure_preserves_error_and_aborts_callback(self):
        self.check_mode('gate-failure')

    def test_successful_gate_keeps_original_call_order(self):
        self.check_mode('success')

    def test_slot_a_publishes_ready_without_moving_barrier(self):
        self.check_mode('slot-a')

    def test_attempt_resets_ready_before_fork(self):
        self.check_mode('reset-ready')


if __name__ == '__main__':
    unittest.main()
