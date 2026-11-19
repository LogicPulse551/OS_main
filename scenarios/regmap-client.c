/* SPDX-License-Identifier: GPL-2.0
 * K05 sequential/reset acceptance client. Requests call the real kernel regmap;
 * local calculations below are only expected-result checks, not a substitute.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "kconc-regmap.h"

_Static_assert(sizeof(struct kconc_regmap_reset) == 32, "reset ABI");
_Static_assert(sizeof(struct kconc_regmap_op) == 56, "operation ABI");
_Static_assert(sizeof(struct kconc_regmap_status) == 120, "status ABI");
static const char *boolean(bool value) { return value ? "true" : "false"; }
static void status_json(const struct kconc_regmap_status *s) {
  printf("{\"abi\":%u,\"epoch\":%u,\"state\":%u,\"active\":%u,\"completed_mask\":%u,"
         "\"snapshot_valid\":%u,\"values\":[%u,%u,%u,%u]}", s->abi, s->epoch,
         s->state, s->active, s->completed_mask, s->snapshot_valid,
         s->values[0], s->values[1], s->values[2], s->values[3]);
}
static bool roles_empty(const struct kconc_regmap_status *s) {
  const struct kconc_regmap_role zero = {0};
  for (unsigned int i = 0; i < KCONC_REGMAP_ROLES; ++i)
    if (memcmp(&s->roles[i], &zero, sizeof(zero))) return false;
  return true;
}
static bool values_match(const struct kconc_regmap_status *s, const unsigned int *expected) {
  for (unsigned int i = 0; i < KCONC_REGMAP_REGS; ++i) if (s->values[i] != expected[i]) return false;
  return true;
}
static bool ready(const struct kconc_regmap_status *s, unsigned int epoch, const unsigned int *values) {
  return s->abi == KCONC_REGMAP_ABI && s->state == KCONC_REGMAP_READY &&
      s->epoch == epoch && epoch && !s->active && !s->completed_mask &&
      s->snapshot_valid == 1 && roles_empty(s) && values_match(s, values);
}
static bool empty(const struct kconc_regmap_status *s) {
  const unsigned int zeros[KCONC_REGMAP_REGS] = {0};
  return s->state == KCONC_REGMAP_EMPTY && !s->active && !s->completed_mask &&
      s->snapshot_valid == 1 && roles_empty(s) && values_match(s, zeros);
}
static int get_status(int fd, struct kconc_regmap_status *s) {
  *s = (struct kconc_regmap_status){.abi = KCONC_REGMAP_ABI};
  return ioctl(fd, KCONC_REGMAP_STATUS, s);
}
static int baseline(unsigned int rounds) {
  int fd = open(KCONC_REGMAP_DEVICE, O_RDWR | O_CLOEXEC);
  if (fd < 0) { printf("{\"kind\":\"kconc.regmap-baseline\",\"passed\":false,\"stage\":\"open\",\"errno\":%d}\n", errno); return 1; }
  bool passed = true;
  unsigned int previous_epoch = 0, done = 0, tid = (unsigned int)syscall(SYS_gettid);
  printf("{\"schema_version\":1,\"kind\":\"kconc.regmap-baseline\",\"requested_rounds\":%u,\"caller_tid\":%u,\"rounds\":[", rounds, tid);
  for (unsigned int n = 0; n < rounds; ++n) {
    struct kconc_regmap_reset reset = {.abi = KCONC_REGMAP_ABI};
    for (unsigned int i = 0; i < KCONC_REGMAP_REGS; ++i) reset.initial[i] = (n + 1) * 16U + i * 4U;
    int reset_rc = ioctl(fd, KCONC_REGMAP_RESET, &reset), reset_errno = reset_rc < 0 ? errno : 0;
    struct kconc_regmap_status initial;
    int initial_rc = get_status(fd, &initial);
    bool initial_ok = reset_rc == 0 && initial_rc == 0 && reset.epoch == previous_epoch + 1 && ready(&initial, reset.epoch, reset.initial);
    bool row_ok = initial_ok;
    printf("%s{\"round\":%u,\"reset_rc\":%d,\"reset_errno\":%d,\"initial_passed\":%s,\"initial\":", n ? "," : "", n, reset_rc, reset_errno, boolean(initial_ok));
    status_json(&initial);
    bool same_register = (n & 1U) != 0;
    bool reversed = (n & 2U) != 0;
    printf(",\"order\":\"%s\",\"same_register\":%s,\"operations\":[", reversed ? "B-A" : "A-B", boolean(same_register));
    unsigned int expected[KCONC_REGMAP_REGS]; memcpy(expected, reset.initial, sizeof(expected));
    for (unsigned int index = 0; index < KCONC_REGMAP_ROLES && initial_ok; ++index) {
      unsigned int role = reversed ? 1U - index : index;
      unsigned int reg = same_register ? 0 : role;
      struct kconc_regmap_op op = {.abi = KCONC_REGMAP_ABI, .epoch = reset.epoch,
          .role = role, .reg = reg, .mask = 1U << role, .value = 1U << role};
      unsigned int expected_before = expected[reg];
      expected[reg] = (expected_before & ~op.mask) | (op.value & op.mask);
      int rc = ioctl(fd, KCONC_REGMAP_OP, &op), saved_errno = rc < 0 ? errno : 0;
      bool valid = rc == 0 && !op.status && op.epoch == reset.epoch && op.role == role && op.reg == reg &&
          op.before == expected_before && op.after == expected[reg] && op.pid == tid &&
          op.checkpoint == reset.epoch && !op.preempt_count && !op.irqs_disabled;
      row_ok &= valid;
      printf("%s{\"role\":%u,\"reg\":%u,\"rc\":%d,\"errno\":%d,\"passed\":%s,"
             "\"before\":%u,\"after\":%u,\"expected_before\":%u,\"expected_after\":%u,"
             "\"pid\":%u,\"checkpoint\":%u,\"preempt_count\":%u,\"irqs_disabled\":%u}",
             index ? "," : "", role, reg, rc, saved_errno, boolean(valid), op.before, op.after,
             expected_before, expected[reg], op.pid, op.checkpoint, op.preempt_count, op.irqs_disabled);
    }
    struct kconc_regmap_status final;
    int final_rc = get_status(fd, &final);
    row_ok &= final_rc == 0 && final.state == KCONC_REGMAP_READY && final.snapshot_valid == 1 &&
        !final.active && final.epoch == reset.epoch && final.completed_mask == 3 && values_match(&final, expected);
    for (unsigned int role = 0; role < KCONC_REGMAP_ROLES; ++role)
      row_ok &= final.roles[role].started == 1 && final.roles[role].completed == 1 &&
          final.roles[role].pid == tid && final.roles[role].checkpoint == reset.epoch &&
          !final.roles[role].status && !final.roles[role].preempt_count && !final.roles[role].irqs_disabled;
    printf("],\"final\":"); status_json(&final);
    printf(",\"passed\":%s}", boolean(row_ok)); fflush(stdout);
    ++done; previous_epoch = reset.epoch; passed &= row_ok;
    if (!row_ok) break;
  }
  struct kconc_regmap_status final = {.abi = KCONC_REGMAP_ABI};
  int teardown_rc = ioctl(fd, KCONC_REGMAP_TEARDOWN, &final);
  bool cleaned = teardown_rc == 0 && empty(&final);
  int close_rc = close(fd);
  passed &= cleaned && close_rc == 0 && done == rounds;
  printf("],\"completed_rounds\":%u,\"teardown_rc\":%d,\"teardown\":", done, teardown_rc);
  status_json(&final);
  printf(",\"resources_closed\":%s,\"passed\":%s,\"kernel_bug_claim\":false,"
         "\"scope\":\"Sequential real-regmap input/reset checks; not concurrent bug or K10 replay acceptance\"}\n",
         boolean(cleaned && close_rc == 0), boolean(passed));
  return passed ? 0 : 1;
}
static int fault_reset(void) {
  int fd = open(KCONC_REGMAP_DEVICE, O_RDWR | O_CLOEXEC);
  if (fd < 0) { printf("{\"kind\":\"kconc.regmap-reset-fault\",\"passed\":false,\"stage\":\"open\",\"errno\":%d}\n", errno); return 1; }
  struct kconc_regmap_reset initial = {.abi = KCONC_REGMAP_ABI};
  int initial_rc = ioctl(fd, KCONC_REGMAP_RESET, &initial);
  struct kconc_regmap_reset bad = {.abi = KCONC_REGMAP_ABI, .flags = KCONC_REGMAP_RESET_FAIL, .initial = {16, 32, 48, 64}};
  int fault_rc = ioctl(fd, KCONC_REGMAP_RESET, &bad), fault_errno = fault_rc < 0 ? errno : 0;
  struct kconc_regmap_status poisoned;
  int status_rc = get_status(fd, &poisoned);
  struct kconc_regmap_op op = {.abi = KCONC_REGMAP_ABI, .epoch = poisoned.epoch, .role = 0, .reg = 0, .mask = 1, .value = 1};
  int op_rc = ioctl(fd, KCONC_REGMAP_OP, &op), op_errno = op_rc < 0 ? errno : 0;
  struct kconc_regmap_reset retry = {.abi = KCONC_REGMAP_ABI};
  int retry_rc = ioctl(fd, KCONC_REGMAP_RESET, &retry), retry_errno = retry_rc < 0 ? errno : 0;
  struct kconc_regmap_status torn = {.abi = KCONC_REGMAP_ABI};
  int teardown_rc = ioctl(fd, KCONC_REGMAP_TEARDOWN, &torn);
  int after_teardown_reset_rc = ioctl(fd, KCONC_REGMAP_RESET, &retry);
  int after_teardown_reset_errno = after_teardown_reset_rc < 0 ? errno : 0;
  int close_rc = close(fd);
  bool failed_closed = initial_rc == 0 && fault_rc == -1 && fault_errno == EIO && status_rc == 0 &&
      poisoned.state == KCONC_REGMAP_POISONED && !poisoned.active && poisoned.snapshot_valid == 1 &&
      poisoned.values[0] != bad.initial[0] && poisoned.values[1] == bad.initial[1] &&
      poisoned.values[2] == bad.initial[2] && poisoned.values[3] == bad.initial[3] &&
      op_rc == -1 && op_errno == EUCLEAN && retry_rc == -1 && retry_errno == EUCLEAN &&
      teardown_rc == 0 && torn.state == KCONC_REGMAP_POISONED && !torn.active && close_rc == 0 &&
      after_teardown_reset_rc == -1 && after_teardown_reset_errno == EUCLEAN;
  fd = open(KCONC_REGMAP_DEVICE, O_RDWR | O_CLOEXEC);
  struct kconc_regmap_reset fresh = {.abi = KCONC_REGMAP_ABI};
  int fresh_rc = fd >= 0 ? ioctl(fd, KCONC_REGMAP_RESET, &fresh) : -1;
  struct kconc_regmap_status fresh_status = {.abi = KCONC_REGMAP_ABI};
  int fresh_status_rc = fd >= 0 ? get_status(fd, &fresh_status) : -1;
  bool reopened = fd >= 0 && fresh_rc == 0 && fresh.epoch == 1 && fresh_status_rc == 0 && ready(&fresh_status, fresh.epoch, fresh.initial);
  struct kconc_regmap_op fresh_op = {.abi = KCONC_REGMAP_ABI, .epoch = fresh.epoch,
      .role = 0, .reg = 0, .mask = 1, .value = 1};
  int fresh_op_rc = fd >= 0 ? ioctl(fd, KCONC_REGMAP_OP, &fresh_op) : -1;
  bool fresh_op_ok = fresh_op_rc == 0 && fresh_op.before == 0 && fresh_op.after == 1 &&
      fresh_op.pid == (unsigned int)syscall(SYS_gettid) && fresh_op.checkpoint == fresh.epoch &&
      !fresh_op.status && !fresh_op.preempt_count && !fresh_op.irqs_disabled;
  struct kconc_regmap_status fresh_torn = {.abi = KCONC_REGMAP_ABI};
  int fresh_teardown = fd >= 0 ? ioctl(fd, KCONC_REGMAP_TEARDOWN, &fresh_torn) : -1;
  int fresh_close = fd >= 0 ? close(fd) : -1;
  bool passed = failed_closed && reopened && fresh_op_ok && fresh_teardown == 0 && empty(&fresh_torn) && fresh_close == 0;
  printf("{\"schema_version\":1,\"kind\":\"kconc.regmap-reset-fault\",\"injected\":true,\"kernel_bug_claim\":false,"
         "\"initial_reset_rc\":%d,\"fault_rc\":%d,\"fault_errno\":%d,\"poisoned\":", initial_rc, fault_rc, fault_errno);
  status_json(&poisoned);
  printf(",\"operation_rc\":%d,\"operation_errno\":%d,\"reset_retry_rc\":%d,\"reset_retry_errno\":%d,"
         "\"teardown_rc\":%d,\"poison_after_teardown\":%s,\"close_rc\":%d,"
         "\"after_teardown_reset_rc\":%d,\"after_teardown_reset_errno\":%d,\"failed_closed\":%s,\"fresh_open_ready\":%s,\"fresh_status\":",
         op_rc, op_errno, retry_rc, retry_errno, teardown_rc, boolean(torn.state == KCONC_REGMAP_POISONED), close_rc,
         after_teardown_reset_rc, after_teardown_reset_errno, boolean(failed_closed), boolean(reopened));
  status_json(&fresh_status);
  printf(",\"fresh_operation_rc\":%d,\"fresh_operation_passed\":%s,\"fresh_operation_before\":%u,\"fresh_operation_after\":%u,"
         "\"fresh_teardown_rc\":%d,\"fresh_close_rc\":%d,\"passed\":%s,"
         "\"scope\":\"Poisoned per-open regmap is rejected until close/reopen; this is not guest-wide recovery\"}\n",
         fresh_op_rc, boolean(fresh_op_ok), fresh_op.before, fresh_op.after, fresh_teardown, fresh_close, boolean(passed));
  return passed ? 0 : 1;
}
int main(int argc, char **argv) {
  if (argc == 2 && !strcmp(argv[1], "fault-reset")) return fault_reset();
  if ((argc == 2 || argc == 4) && !strcmp(argv[1], "baseline")) {
    unsigned long rounds = 20;
    if (argc == 4) {
      char *end = NULL; errno = 0;
      rounds = strtoul(argv[3], &end, 10);
      if (strcmp(argv[2], "--rounds") || !*argv[3] || *end || errno || rounds < 1 || rounds > 1000) goto usage;
    }
    return baseline((unsigned int)rounds);
  }
usage:
  fprintf(stderr, "Usage: %s baseline [--rounds 1..1000] | fault-reset\n", argv[0]);
  return 2;
}
