"""Actual 0005 C helpers/hooks under context stubs, without a kernel or VM.

This validates recorder context and paired state bookkeeping. It does not prove
all IRQ/remote behavior or replace the new kernel's real strict-path regression.
"""
from pathlib import Path
import copy
import importlib.util
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
PATCH = REPO / 'patches/maccconc/0005-k11-irq-tail.patch'
spec = importlib.util.spec_from_file_location('k11_irq_policy_analysis', REPO / 'adapters/maccconc/k11_analysis.py')
analysis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analysis)


def images():
    """Keep both sides of the complete-function patch context, by source file."""
    result, filename, in_hunk = {}, None, False
    for row in PATCH.read_text().splitlines(keepends=True):
        if row.startswith('diff --git '):
            filename = None; in_hunk = False
        elif row.startswith('+++ b/'):
            filename = row[len('+++ b/'):].strip()
            result[filename] = [[], []]
        elif row.startswith('@@ '):
            in_hunk = True
        elif filename and in_hunk:
            if row.startswith((' ', '-')): result[filename][0].append(row[1:])
            if row.startswith((' ', '+')): result[filename][1].append(row[1:])
    return {name: tuple(''.join(side) for side in pair) for name, pair in result.items()}


def function(text, signature):
    start = text.index(signature)
    left = text.index('{', start)
    depth = 0
    for position in range(left, len(text)):
        if text[position] == '{': depth += 1
        elif text[position] == '}':
            depth -= 1
            if depth == 0: return text[start:position + 1]
    raise AssertionError('Patch context does not contain complete function ' + signature)


def macro(text, name):
    rows = text.splitlines()
    start = next(i for i, row in enumerate(rows) if row.startswith('#define ' + name + '('))
    end = start
    while rows[end].endswith('\\'): end += 1
    return '\n'.join(rows[start:end + 1])


class IrqTailSourceTests(unittest.TestCase):
    def test_only_three_actual_async_idt_macros_are_bracketed(self):
        files = images()
        self.assertEqual(set(files), {'arch/x86/include/asm/idtentry.h', 'include/linux/kcov.h',
                                     'include/linux/sched.h', 'kernel/kcov.c'})
        before, after = files['arch/x86/include/asm/idtentry.h']
        self.assertNotIn('kcov_async_irq_enter()', before)
        self.assertEqual(after.count('kcov_async_irq_enter();'), 3)
        self.assertEqual(after.count('kcov_async_irq_exit();'), 3)
        for name in ('DEFINE_IDTENTRY_IRQ', 'DEFINE_IDTENTRY_SYSVEC', 'DEFINE_IDTENTRY_SYSVEC_SIMPLE'):
            body = macro(after, name)
            self.assertEqual(body.count('kcov_async_irq_enter();'), 1)
            self.assertEqual(body.count('kcov_async_irq_exit();'), 1)
            self.assertLess(body.index('kcov_async_irq_enter();'), body.index('irqentry_enter(regs)'))
            self.assertLess(body.index('irqentry_exit(regs, state);'), body.index('kcov_async_irq_exit();'))
            protected = body[body.index('kcov_async_irq_enter();'):body.index('kcov_async_irq_exit();')]
            self.assertNotRegex(protected, r'\breturn\b|\bgoto\b')
        self.assertNotIn('irqentry_enter(', '\n'.join(line[1:] for line in PATCH.read_text().splitlines()
            if line.startswith('+') and not line.startswith('+++') and 'state =' not in line))

    def test_depth_changes_only_at_paired_helpers_and_task_initialization(self):
        files = images()
        before, after = files['kernel/kcov.c']
        init = function(after, 'void kcov_task_init(')
        self.assertIn('t->kcov_async_irq_depth = 0;', init)
        self.assertLess(init.index('kcov_async_irq_depth = 0'), init.index('kcov_task_reset(t)'))
        self.assertNotIn('kcov_async_irq_depth', function(after, 'static void kcov_task_reset('))
        writes = [line.strip() for line in after.splitlines() if re.search(r'kcov_async_irq_depth\s*=', line)]
        self.assertEqual(writes, ['t->kcov_async_irq_depth = 0;'])
        header = files['include/linux/kcov.h'][1]
        enter = function(header, 'static __always_inline void kcov_async_irq_enter(')
        leave = function(header, 'static __always_inline void kcov_async_irq_exit(')
        self.assertIn('READ_ONCE(current->kcov_async_irq_depth) + 1', enter)
        self.assertIn('READ_ONCE(current->kcov_async_irq_depth) - 1', leave)
        self.assertIn('barrier();', enter)
        self.assertIn('barrier();', leave)
        self.assertNotRegex(enter + leave, r'local_irq_|preempt_(disable|enable)|this_cpu|raw_cpu')
        self.assertIn('static __always_inline void kcov_async_irq_enter(void) {}', header)
        self.assertIn('static __always_inline void kcov_async_irq_exit(void) {}', header)

    def test_entry_exit_reject_async_context_before_any_di_or_ctxsw_mutation(self):
        after = images()['kernel/kcov.c'][1]
        for signature in ('void notrace __sanitizer_cov_trace_pc_entry(', 'void notrace __sanitizer_cov_trace_pc_exit('):
            body = function(after, signature)
            guard = body.index('READ_ONCE(cur->kcov_async_irq_depth)')
            self.assertLess(guard, body.index('if (kcov_mode & KCOV_IN_CTXSW)'))
            self.assertLess(guard, body.index('kcov_add_pc_record'))
            self.assertIn('!(in_softirq_really() && cur->kcov_softirq)', body)
        self.assertIn('READ_ONCE(t->kcov_async_irq_depth)', function(after, 'static notrace bool check_kcov_context('))

    def test_scope_explicitly_excludes_uncovered_entry_backends(self):
        text = PATCH.read_text()
        self.assertIn('CONFIG_X86_FRED', text)
        self.assertIn('CONFIG_XEN', text)
        self.assertIn('nested remote/IRQ', text)


class RecorderIdentityTests(unittest.TestCase):
    def fixture(self):
        root = '/synthetic/new-irq-recorder'
        patch_sha = analysis.sha(PATCH.read_bytes())
        builder_sha = analysis.sha((REPO / analysis.RECORDER_BUILDER).read_bytes())
        sources = [dict(path=root + '/' + name, sha256=str(index+2)*64) for index, name in enumerate(analysis.RECORDER_SOURCES)]
        kernel = dict(source=root, recorder_policy_id=analysis.RECORDER_POLICY_ID,
                      recorder_patch=dict(path=analysis.RECORDER_PATCH, sha256=patch_sha), recorder_sources=sources,
                      build_script_path=analysis.RECORDER_BUILDER, build_script_sha256=builder_sha,
                      parent_control_sha256='1'*64, patched_kcov_sha256=sources[-1]['sha256'])
        team = {analysis.RECORDER_PATCH: patch_sha, analysis.RECORDER_BUILDER: builder_sha}
        return kernel, team

    def test_registered_policy_binds_four_exact_sources_and_patch(self):
        kernel, team = self.fixture()
        result = analysis.verify_recorder_contract(kernel, team)
        self.assertEqual(result['policy_id'], analysis.RECORDER_POLICY_ID)
        self.assertEqual(set(result['sources']), set(analysis.RECORDER_SOURCES))
        self.assertIsNone(analysis.verify_recorder_contract({'patched_kcov_sha256': 'a'*64}, {}))

    def test_unknown_or_partial_policy_cannot_be_treated_as_legacy(self):
        for damage in ('unknown', 'only-patch', 'missing-sources'):
            kernel, team = self.fixture()
            if damage == 'unknown': kernel['recorder_policy_id'] = 'unverified'
            elif damage == 'only-patch': kernel = {'recorder_patch': kernel['recorder_patch']}
            else: del kernel['recorder_sources']
            with self.subTest(damage=damage), self.assertRaises(ValueError):
                analysis.verify_recorder_contract(kernel, team)

    def test_changed_patch_or_unregistered_builder_rejected(self):
        for damage in ('patch', 'patch-team', 'builder', 'builder-team'):
            kernel, team = self.fixture()
            if damage == 'patch': kernel['recorder_patch']['sha256'] = '0'*64
            elif damage == 'patch-team': team[analysis.RECORDER_PATCH] = '0'*64
            elif damage == 'builder': kernel['build_script_path'] = 'scripts/build-k11-kernel.py'
            else: team[analysis.RECORDER_BUILDER] = '0'*64
            with self.subTest(damage=damage), self.assertRaises(ValueError):
                analysis.verify_recorder_contract(kernel, team)

    def test_missing_duplicate_other_root_or_original_kcov_rejected(self):
        for damage in ('missing', 'duplicate', 'root', 'unchanged', 'unbound-kcov', 'traversal'):
            kernel, team = self.fixture()
            if damage == 'missing': kernel['recorder_sources'].pop()
            elif damage == 'duplicate': kernel['recorder_sources'].append(copy.deepcopy(kernel['recorder_sources'][0]))
            elif damage == 'root': kernel['recorder_sources'][0]['path'] = '/other/arch/x86/include/asm/idtentry.h'
            elif damage == 'unchanged': kernel['parent_control_sha256'] = kernel['patched_kcov_sha256']
            elif damage == 'unbound-kcov': kernel['patched_kcov_sha256'] = 'e'*64
            else: kernel['source'] = '/synthetic/../new-irq-recorder'
            with self.subTest(damage=damage), self.assertRaises(ValueError):
                analysis.verify_recorder_contract(kernel, team)


PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#define CONFIG_X86_64 1
#define CONFIG_KCOV_MEMORY 1
#define IS_ENABLED(x) (x)
#define notrace
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,y) do { (x)=(y); } while(0)
#define barrier() __asm__ __volatile__("" ::: "memory")
#define raw_cpu_read(x) (irq_stack)
#define likely(x) (x)
#define unlikely(x) (x)
#define _RET_IP_ 123UL
#define __builtin_return_address(n) ((void*)0)
#define KCOV_ENABLE_MEMORY (1U << 28)
#define KCOV_EXT_FORMAT (1U << 29)
#define KCOV_IN_CTXSW (1U << 30)
#define KCOV_MODE_TRACE_PC 2U
#define KCOV_MODE_TRACE_PC_EXT (KCOV_MODE_TRACE_PC|KCOV_EXT_FORMAT)
#define KCOV_RECORD_IP_MASK (~0UL)
#define KCOV_RECORDFLAG_TYPE_ENTRY 0UL
#define KCOV_RECORDFLAG_TYPE_EXIT 1UL
struct di_stack { unsigned int nomatch_depth; };
struct kcov {
 int suppressed_stack_delta, suppressed_stack_mindelta;
 struct { unsigned int num_match_stacks, shared_nomatch_depth, stack_used;
          struct di_stack match_stacks[1]; } di;
};
struct task_struct {
 unsigned int kcov_async_irq_depth, kcov_mode;
 bool kcov_softirq;
 struct kcov *kcov;
 void *kcov_remote;
 unsigned long kcov_handle;
};
static struct task_struct *current;
static bool task_context=true, softirq_context=false, irq_stack=false;
static unsigned int records, slow_entries;
static bool in_task(void) { return task_context; }
static bool in_softirq_really(void) { return softirq_context; }
static unsigned long canonicalize_ip(unsigned long ip) { return ip; }
static void kcov_add_pc_record(struct task_struct *t,unsigned long r,bool e,unsigned long caller) {
 (void)t;(void)r;(void)e;(void)caller; records++;
}
static void kcov_di_enter_slowpath(struct kcov *k,unsigned long ip) { (void)ip;slow_entries++;k->di.stack_used++; }
static void kcov_task_reset(struct task_struct *t) { t->kcov_mode=0; }
'''

MAIN = r'''
int main(void) {
 struct kcov ka={0}, kb={0};
 struct task_struct a={.kcov=&ka}, b={.kcov=&kb};current=&a;
 a.kcov_async_irq_depth=9;a.kcov_handle=42;kcov_task_init(&b);
 assert(b.kcov_async_irq_depth==0 && b.kcov_handle==42);
 a.kcov_async_irq_depth=0;
 assert(check_kcov_context(&a));
 kcov_async_irq_enter();
 assert(a.kcov_async_irq_depth==1 && !check_kcov_context(&a));
 /* The hardirq counter/stack are already clear: this is the observed tail. */
 task_context=true;irq_stack=false;assert(!check_kcov_context(&a));
 kcov_async_irq_enter();assert(a.kcov_async_irq_depth==2);
 kcov_async_irq_exit();assert(a.kcov_async_irq_depth==1 && !check_kcov_context(&a));
 /* irqentry_exit may schedule another task, which must not inherit the guard. */
 current=&b;assert(check_kcov_context(&b));
 kcov_async_irq_enter();assert(b.kcov_async_irq_depth==1 && a.kcov_async_irq_depth==1);
 kcov_async_irq_exit();assert(b.kcov_async_irq_depth==0);
 current=&a;
 a.kcov_mode=KCOV_MODE_TRACE_PC_EXT|KCOV_ENABLE_MEMORY;
 ka.di.num_match_stacks=1;ka.di.shared_nomatch_depth=3;ka.di.stack_used=2;
 ka.di.match_stacks[0].nomatch_depth=4;
 __sanitizer_cov_trace_pc_entry();__sanitizer_cov_trace_pc_exit();
 assert(records==0 && slow_entries==0 && ka.di.shared_nomatch_depth==3);
 assert(ka.di.stack_used==2 && ka.di.match_stacks[0].nomatch_depth==4);
 a.kcov_mode|=KCOV_IN_CTXSW;
 __sanitizer_cov_trace_pc_entry();__sanitizer_cov_trace_pc_exit();
 assert(ka.suppressed_stack_delta==0 && ka.suppressed_stack_mindelta==0);
 assert(ka.di.shared_nomatch_depth==3 && records==0);
 /* Preserve only the inherited explicit remote-softirq exception. */
 task_context=false;softirq_context=true;a.kcov_softirq=true;
 assert(check_kcov_context(&a));
 a.kcov_mode&=~KCOV_IN_CTXSW;
 __sanitizer_cov_trace_pc_entry();assert(records==1 && ka.di.shared_nomatch_depth==4);
 __sanitizer_cov_trace_pc_exit();assert(records==2 && ka.di.shared_nomatch_depth==3);
 a.kcov_softirq=false;assert(!check_kcov_context(&a));
 assert(a.kcov_async_irq_depth==1); /* Remote flags did not reset paired state. */
 a.kcov_softirq=true;softirq_context=false;assert(!check_kcov_context(&a));
 a.kcov_softirq=false;task_context=true;
 kcov_async_irq_exit();assert(a.kcov_async_irq_depth==0 && check_kcov_context(&a));
 /* The ordinary task/ctxsw DI behavior is still used after the IRQ ends. */
 __sanitizer_cov_trace_pc_entry();assert(records==3 && ka.di.shared_nomatch_depth==4);
 __sanitizer_cov_trace_pc_exit();assert(records==4 && ka.di.shared_nomatch_depth==3);
 a.kcov_mode|=KCOV_IN_CTXSW;
 __sanitizer_cov_trace_pc_entry();assert(ka.suppressed_stack_delta==1);
 __sanitizer_cov_trace_pc_exit();assert(ka.suppressed_stack_delta==0);
 assert(a.kcov_async_irq_depth==0 && b.kcov_async_irq_depth==0);
 return 0;
}
'''


@unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('cc'), 'Linux C compiler required')
class IrqTailBehaviorTests(unittest.TestCase):
    def test_actual_helpers_guard_hooks_nested_task_switch_and_remote_exception(self):
        files = images();header = files['include/linux/kcov.h'][1];kcov = files['kernel/kcov.c'][1]
        bodies = '\n'.join(function(header, name) for name in (
            'static __always_inline void kcov_async_irq_enter(', 'static __always_inline void kcov_async_irq_exit('))
        bodies += '\n' + '\n'.join(function(kcov, name) for name in (
            'static notrace bool check_kcov_context(', 'void notrace __sanitizer_cov_trace_pc_entry(',
            'void notrace __sanitizer_cov_trace_pc_exit(', 'void kcov_task_init('))
        with tempfile.TemporaryDirectory(prefix='k11-irq-tail-') as directory:
            root = Path(directory);code = root/'guard.c';exe = root/'guard'
            code.write_text(PRELUDE + bodies + MAIN)
            built = subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Werror', str(code), '-o', str(exe)], capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            tested = subprocess.run([str(exe)], capture_output=True, text=True, timeout=5)
            self.assertEqual(tested.returncode, 0, tested.stdout + tested.stderr)


if __name__ == '__main__':
    unittest.main()
