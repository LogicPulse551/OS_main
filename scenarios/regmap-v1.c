/* SPDX-License-Identifier: GPL-2.0
 * K05 user adapter: real regmap operations run synchronously in the ioctl
 * caller. Distinct registers make this a lifecycle/control test, not a bug.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "kconc-regmap.h"

#define MAX_FDS 4096
_Static_assert(sizeof(struct kconc_regmap_reset) == 32, "reset ABI");
_Static_assert(sizeof(struct kconc_regmap_op) == 56, "operation ABI");
_Static_assert(sizeof(struct kconc_regmap_status) == 120, "status ABI");
static int device_fd = -1;
static unsigned int epoch, calls[2], tids[2];
static int op_rc[2], op_errno[2];
static struct kconc_regmap_op operations[2];
static int initial_fds[MAX_FDS];
static size_t initial_count;
static bool setup_fault;

static const char *boolean(bool value) { return value ? "true" : "false"; }
static int compare_fd(const void *a, const void *b) {
  int left = *(const int *)a, right = *(const int *)b;
  return (left > right) - (left < right);
}
static bool collect_fds(int *fds, size_t *count) {
  DIR *dir = opendir("/proc/self/fd");
  if (!dir) return false;
  int own = dirfd(dir);
  *count = 0;
  errno = 0;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    char *end = NULL;
    long value = strtol(entry->d_name, &end, 10);
    if (!*entry->d_name || *end || value < 0 || value > INT_MAX || value == own) continue;
    if (*count == MAX_FDS) { closedir(dir); return false; }
    fds[(*count)++] = (int)value;
  }
  int read_error = errno;
  if (closedir(dir) || read_error) return false;
  qsort(fds, *count, sizeof(*fds), compare_fd);
  return true;
}
static bool same_fds(const int *a, size_t na, const int *b, size_t nb) {
  return na == nb && !memcmp(a, b, na * sizeof(*a));
}
static void fds_json(const int *fds, size_t count) {
  putchar('[');
  for (size_t i = 0; i < count; ++i) printf("%s%d", i ? "," : "", fds[i]);
  putchar(']');
}
static void phase_end(void) {
  puts("}");
  if (fflush(stdout)) _exit(74);
}
static bool zero_roles(const struct kconc_regmap_status *status) {
  const struct kconc_regmap_role zero = {0};
  return !memcmp(&status->roles[0], &zero, sizeof(zero)) &&
         !memcmp(&status->roles[1], &zero, sizeof(zero));
}
static bool initial_status(const struct kconc_regmap_status *status) {
  return status->abi == KCONC_REGMAP_ABI && status->state == KCONC_REGMAP_READY &&
         status->epoch == epoch && epoch && !status->active && !status->completed_mask &&
         status->snapshot_valid == 1 && !status->values[0] && !status->values[1] &&
         !status->values[2] && !status->values[3] && zero_roles(status);
}
static bool teardown(void) {
  struct kconc_regmap_status status = {.abi = KCONC_REGMAP_ABI};
  int rc = device_fd >= 0 ? ioctl(device_fd, KCONC_REGMAP_TEARDOWN, &status) : -1;
  int saved_errno = rc < 0 ? errno : 0;
  bool empty = rc == 0 && (status.state == KCONC_REGMAP_EMPTY ||
      (setup_fault && status.state == KCONC_REGMAP_POISONED)) && !status.active &&
      !status.completed_mask && status.snapshot_valid == 1 && zero_roles(&status);
  for (unsigned int i = 0; i < KCONC_REGMAP_REGS; ++i) empty &= status.values[i] == 0;
  int close_rc = device_fd >= 0 ? close(device_fd) : 0;
  device_fd = -1;
  int actual[MAX_FDS]; size_t count = 0;
  bool observed = collect_fds(actual, &count);
  bool restored = observed && same_fds(initial_fds, initial_count, actual, count);
  bool passed = empty && close_rc == 0 && restored;
  printf("KCONC_PHASE {\"phase\":\"teardown\",\"passed\":%s,\"ioctl_rc\":%d,"
         "\"errno\":%d,\"map_empty\":%s,\"resources_closed\":%s,\"context_state\":%u,"
         "\"active\":%u,\"completed_mask\":%u,\"snapshot_valid\":%u,\"values\":[%u,%u,%u,%u],\"roles_zero\":%s,"
         "\"fd_set_restored\":%s,\"fd_snapshot_observed\":%s,\"expected_fds\":",
         boolean(passed), rc, saved_errno, boolean(empty), boolean(close_rc == 0), status.state,
         status.active, status.completed_mask, status.snapshot_valid,
         status.values[0], status.values[1], status.values[2], status.values[3], boolean(zero_roles(&status)),
         boolean(restored), boolean(observed));
  fds_json(initial_fds, initial_count);
  printf(",\"actual_fds\":"); fds_json(actual, count); phase_end();
  return passed;
}

void test_setup(void) {
  const char *fault = getenv("KCONC_FAULT");
  setup_fault = fault && !strcmp(fault, "setup");
  bool fault_valid = !fault || !*fault || !strcmp(fault, "none") || setup_fault;
  memset(calls, 0, sizeof(calls)); memset(tids, 0, sizeof(tids));
  memset(operations, 0, sizeof(operations));
  op_rc[0] = op_rc[1] = -1; op_errno[0] = op_errno[1] = 0;
  bool observed = collect_fds(initial_fds, &initial_count);
  if (observed && fault_valid) device_fd = open(KCONC_REGMAP_DEVICE, O_RDWR | O_CLOEXEC);
  struct kconc_regmap_reset reset = {.abi = KCONC_REGMAP_ABI,
      .flags = setup_fault ? KCONC_REGMAP_RESET_FAIL : 0};
  int rc = device_fd >= 0 ? ioctl(device_fd, KCONC_REGMAP_RESET, &reset) : -1;
  int saved_errno = rc < 0 ? errno : 0;
  epoch = reset.epoch;
  bool setup_ok = observed && fault_valid && device_fd >= 0 && rc == 0 && epoch;
  printf("KCONC_PHASE {\"phase\":\"setup\",\"passed\":%s,\"fault\":\"%s\","
         "\"injected\":%s,\"fd\":%d,\"reset_rc\":%d,\"errno\":%d,\"epoch\":%u,\"initial_fds\":",
         boolean(setup_ok), setup_fault ? "setup" : "none", boolean(setup_fault), device_fd, rc, saved_errno, epoch);
  fds_json(initial_fds, initial_count); phase_end();
  if (!setup_ok) { (void)teardown(); _exit(71); }
  struct kconc_regmap_status status = {.abi = KCONC_REGMAP_ABI};
  rc = ioctl(device_fd, KCONC_REGMAP_STATUS, &status);
  int actual[MAX_FDS], expected[MAX_FDS]; size_t count = 0, expected_count = initial_count;
  observed = collect_fds(actual, &count);
  memcpy(expected, initial_fds, initial_count * sizeof(*expected));
  bool room = initial_count < MAX_FDS;
  if (room) { expected[expected_count++] = device_fd; qsort(expected, expected_count, sizeof(*expected), compare_fd); }
  bool matches = room && observed && same_fds(expected, expected_count, actual, count);
  bool ready = rc == 0 && initial_status(&status);
  bool passed = ready && matches;
  printf("KCONC_PHASE {\"phase\":\"initial_state\",\"passed\":%s,\"epoch\":%u,"
         "\"regmap_ready\":%s,\"values\":[%u,%u,%u,%u],\"active\":%u,"
         "\"completed_mask\":%u,\"fd_set_matches\":%s,\"snapshot_valid\":%u,\"context_state\":%u,\"roles_zero\":%s",
         boolean(passed), status.epoch, boolean(ready), status.values[0], status.values[1],
         status.values[2], status.values[3], status.active, status.completed_mask, boolean(matches),
         status.snapshot_valid, status.state, boolean(zero_roles(&status)));
  phase_end();
  if (!passed) { (void)teardown(); _exit(72); }
}
static void run_operation(unsigned int role) {
  ++calls[role];
  tids[role] = (unsigned int)syscall(SYS_gettid);
  operations[role] = (struct kconc_regmap_op){.abi = KCONC_REGMAP_ABI, .epoch = epoch,
      .role = role, .reg = role, .mask = 1U << role, .value = 1U << role};
  op_rc[role] = ioctl(device_fd, KCONC_REGMAP_OP, &operations[role]);
  op_errno[role] = op_rc[role] < 0 ? errno : 0;
}
void test_thread1(void) { run_operation(0); }
void test_thread2(void) { run_operation(1); }
void test_end(void) {
  bool completed = calls[0] == 1 && calls[1] == 1;
  bool valid = completed;
  printf("KCONC_PHASE {\"phase\":\"operations\",\"a_calls\":%u,\"b_calls\":%u,\"results\":[", calls[0], calls[1]);
  for (unsigned int role = 0; role < 2; ++role) {
    const struct kconc_regmap_op *op = &operations[role];
    valid &= op_rc[role] == 0 && !op->status && op->abi == KCONC_REGMAP_ABI &&
      op->role == role && op->reg == role && op->epoch == epoch && op->before == 0 &&
      op->after == (1U << role) && op->pid == tids[role] && tids[role] &&
      op->checkpoint == epoch && !op->preempt_count && !op->irqs_disabled;
    printf("%s{\"role\":%u,\"reg\":%u,\"rc\":%d,\"errno\":%d,\"status\":%d,"
           "\"epoch\":%u,\"before\":%u,\"after\":%u,\"caller_tid\":%u,\"kernel_pid\":%u,"
           "\"checkpoint\":%u,\"preempt_count\":%u,\"irqs_disabled\":%u}",
           role ? "," : "", role, op->reg, op_rc[role], op_errno[role], op->status, op->epoch,
           op->before, op->after, tids[role], op->pid, op->checkpoint, op->preempt_count, op->irqs_disabled);
  }
  printf("],\"passed\":%s", boolean(valid)); phase_end();
  struct kconc_regmap_status status = {.abi = KCONC_REGMAP_ABI};
  int rc = ioctl(device_fd, KCONC_REGMAP_STATUS, &status);
  bool property = valid && rc == 0 && status.state == KCONC_REGMAP_READY &&
      status.snapshot_valid == 1 && !status.active && status.epoch == epoch &&
      status.completed_mask == 3 && status.values[0] == 1 && status.values[1] == 2 &&
      !status.values[2] && !status.values[3];
  for (unsigned int role = 0; role < 2; ++role) {
    const struct kconc_regmap_role *slot = &status.roles[role];
    property &= slot->pid == tids[role] && slot->checkpoint == epoch &&
        slot->started == 1 && slot->completed == 1 && !slot->status &&
        !slot->preempt_count && !slot->irqs_disabled && slot->reg == role &&
        slot->before == 0 && slot->after == (1U << role);
  }
  printf("KCONC_PHASE {\"phase\":\"property\",\"passed\":%s,"
         "\"oracle\":\"regmap-disjoint-registers\",\"natural_passed\":%s,\"injected\":false,"
         "\"kernel_bug_claim\":false,\"status_rc\":%d,\"epoch\":%u,\"values\":[%u,%u,%u,%u],"
         "\"snapshot_valid\":%u,\"context_state\":%u,\"active\":%u,\"completed_mask\":%u",
         boolean(property), boolean(property), rc, status.epoch, status.values[0], status.values[1], status.values[2], status.values[3],
         status.snapshot_valid, status.state, status.active, status.completed_mask);
  phase_end();
  bool cleaned = teardown();
  if (!cleaned || !property) _exit(73);
}
