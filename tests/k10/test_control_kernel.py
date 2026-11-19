"""Exercise the actual added C routines without executing a kernel or VM."""
import importlib.util
import pathlib
import shutil
import subprocess
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('k10_kernel_builder', REPO/'scripts/build-k10-kernel.py')
builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)


def patched_hunk(function):
    """Take the new side of the complete function hunk, rather than a model."""
    patch = (REPO/builder.PATCH).read_text(encoding='utf-8')
    for hunk in patch.split('\n@@ ')[1:]:
        lines = hunk.splitlines()[1:]
        value = '\n'.join(line[1:] for line in lines if line.startswith((' ', '+')))
        if function in value:
            return value
    raise AssertionError('Missing complete patched function: '+function)


class IsolatedBuildTests(unittest.TestCase):
    def test_family_names_and_output_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = pathlib.Path(directory)
            _, source, output = builder.new_paths(lab, 'mutex', 'linux-k07-k10-control-01')
            self.assertEqual(source, lab/'sources/linux-k07-k10-control-01')
            output.mkdir(parents=True)
            with self.assertRaises(ValueError):
                builder.new_paths(lab, 'mutex', 'linux-k07-k10-control-01')

    def test_wrong_family_or_traversal_cannot_select_old_build(self):
        with tempfile.TemporaryDirectory() as directory:
            for family, name in [('rmw', 'linux-k07-k10-control-01'), ('mutex', '../linux-k07-01'),
                                 ('mutex', 'linux-k07-01'), ('unknown', 'linux-k10-control')]:
                with self.subTest(family=family, name=name), self.assertRaises(ValueError):
                    builder.new_paths(directory, family, name)

    def test_repository_cannot_be_used_as_build_lab(self):
        with self.assertRaises(ValueError):
            builder.new_paths(REPO/'build-output', 'rmw', 'linux-k06-k10-control-01')

    def test_baseline_change_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); target = root/'kernel'
            target.write_bytes(b'accepted')
            record = builder.snapshot(root, ['kernel'])
            self.assertTrue(builder.unchanged(record))
            target.write_bytes(b'changed')
            self.assertFalse(builder.unchanged(record))

    def test_patch_hunk_lengths_are_well_formed(self):
        import re
        text = (REPO/builder.PATCH).read_text(encoding='utf-8')
        for hunk in text.split('\n@@ ')[1:]:
            header, *lines = hunk.splitlines()
            old_count, new_count = map(int, re.fullmatch(r'-\d+,(\d+) \+\d+,(\d+) @@', header).groups())
            self.assertEqual(sum(line.startswith((' ', '-')) for line in lines), old_count)
            self.assertEqual(sum(line.startswith((' ', '+')) for line in lines), new_count)


@unittest.skipUnless(shutil.which('cc'), 'A C compiler is required for the actual-patch harness')
class ControlCodeTests(unittest.TestCase):
    def compile_and_run(self, x86):
        source = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
typedef uint64_t u64;
#define notrace
#define READ_ONCE(x) (x)
#define raw_cpu_read(x) (irq_stack)
#define barrier() do {} while (0)
struct task_struct { bool kcov_softirq; };
static bool task_context, softirq_context, irq_stack;
static bool in_task(void) { return task_context; }
static bool in_softirq_really(void) { return softirq_context; }
struct kcov { struct { u64 spin_limit; struct kcov *syncbits_owner; unsigned long sync_bits[1]; } di; };
static struct kcov *observed;
static unsigned int relax_calls, wake_after, wake_bit;
static bool test_bit(unsigned int bit, unsigned long *bits) { return !!(bits[0] & (1UL << bit)); }
static void cpu_relax(void) {
  relax_calls++;
  if (wake_after && relax_calls == wake_after) observed->di.sync_bits[0] |= 1UL << wake_bit;
}
'''
        source += patched_hunk('check_kcov_context')+'\n'+patched_hunk('__kcov_spin_wait')
        source += r'''
int main(void) {
  struct task_struct t = { false };
  task_context=true; softirq_context=false; irq_stack=false;
  assert(check_kcov_context(&t));
  irq_stack=true;
#ifdef CONFIG_X86_64
  assert(!check_kcov_context(&t));
#else
  assert(check_kcov_context(&t));
#endif
  task_context=false; softirq_context=true; t.kcov_softirq=true;
  assert(check_kcov_context(&t)); /* Existing explicit remote-softirq exception. */
  t.kcov_softirq=false;
  assert(!check_kcov_context(&t));
  softirq_context=false; t.kcov_softirq=true;
  assert(!check_kcov_context(&t)); /* Hard IRQ/NMI cannot use that exception. */
  task_context=true; irq_stack=false; t.kcov_softirq=false;
  assert(check_kcov_context(&t)); /* Scope deliberately ends when the marker clears. */

  struct kcov owner = {0}; observed=&owner; owner.di.syncbits_owner=&owner;
  owner.di.spin_limit=3; wake_bit=0; wake_after=2; relax_calls=0;
  assert(__kcov_spin_wait(&owner,0)==0 && relax_calls==2);
  assert(owner.di.spin_limit==3); /* gate0 cannot consume WAIT's allowance. */
  wake_bit=1; wake_after=3; relax_calls=0;
  assert(__kcov_spin_wait(&owner,1)==0 && relax_calls==3);
  assert(owner.di.spin_limit==3);
  owner.di.sync_bits[0]=0; wake_after=0; relax_calls=0;
  assert(__kcov_spin_wait(&owner,0)==-ETIMEDOUT && relax_calls==3);
  assert(owner.di.spin_limit==3);
  relax_calls=0;
  assert(__kcov_spin_wait(&owner,1)==-ETIMEDOUT && relax_calls==3);
  owner.di.spin_limit=0; relax_calls=0;
  assert(__kcov_spin_wait(&owner,0)==-ETIMEDOUT && relax_calls==0);
  owner.di.sync_bits[0]=1;
  assert(__kcov_spin_wait(&owner,0)==0 && relax_calls==0);
  return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); path=root/'control.c'; executable=root/'control'
            path.write_text(source, encoding='utf-8')
            command=[shutil.which('cc'), '-std=c11', '-Wall', '-Werror']
            if x86:command.append('-DCONFIG_X86_64=1')
            compiled=subprocess.run([*command, str(path), '-o', str(executable)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode,0,compiled.stdout+compiled.stderr)
            executed=subprocess.run([str(executable)], capture_output=True, text=True)
            self.assertEqual(executed.returncode,0,executed.stdout+executed.stderr)

    def test_x86_irq_tail_remote_exception_and_independent_finite_waits(self):
        self.compile_and_run(True)

    def test_non_x86_preserves_original_context_gate(self):
        self.compile_and_run(False)


if __name__ == '__main__':
    unittest.main()
