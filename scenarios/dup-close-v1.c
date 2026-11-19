/* SPDX-License-Identifier: Apache-2.0
 * K04 lifecycle adapter around the pinned MAccConc dup/close testcase.
 * The original two operations are included unchanged. Fault modes exercise
 * infrastructure reporting and recovery; they are not kernel bug examples.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/types.h>

#define test_setup upstream_test_setup
#define test_thread1 upstream_test_thread1
#define test_thread2 upstream_test_thread2
#define test_end upstream_test_end
#include "testcase/demo-dup-vs-close.c"
#undef test_setup
#undef test_thread1
#undef test_thread2
#undef test_end

#define MAX_FDS 4096
enum fault_mode { FAULT_NONE, FAULT_SETUP, FAULT_HANG, FAULT_CLEANUP, FAULT_PROPERTY };
static enum fault_mode fault;
static const char *fault_name = "none";
static int initial_fds[MAX_FDS];
static size_t initial_count;
static unsigned int a_calls, b_calls;

static const char *boolean(bool value) { return value ? "true" : "false"; }
static int compare_fd(const void *left, const void *right) {
  int a = *(const int *)left, b = *(const int *)right;
  return (a > b) - (a < b);
}
static bool collect_fds(int *fds, size_t *count) {
  DIR *directory = opendir("/proc/self/fd");
  if (!directory) return false;
  int own_fd = dirfd(directory);
  struct dirent *entry;
  *count = 0;
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    char *end = NULL;
    long value = strtol(entry->d_name, &end, 10);
    if (!*entry->d_name || *end || value < 0 || value > INT_MAX || value == own_fd)
      continue;
    if (*count == MAX_FDS) {
      closedir(directory);
      return false;
    }
    fds[(*count)++] = (int)value;
  }
  int read_error = errno;
  if (closedir(directory) || read_error) return false;
  qsort(fds, *count, sizeof(*fds), compare_fd);
  return true;
}
static void print_fds(const int *fds, size_t count) {
  putchar('[');
  for (size_t index = 0; index < count; ++index)
    printf("%s%d", index ? "," : "", fds[index]);
  putchar(']');
}
static bool same_fds(const int *left, size_t left_count, const int *right, size_t right_count) {
  return left_count == right_count && !memcmp(left, right, left_count * sizeof(*left));
}
static void flush_phase(void) {
  putchar('\n');
  if (fflush(stdout)) _exit(74);
}
static bool parse_fault(void) {
  const char *value = getenv("KCONC_FAULT");
  if (!value || !*value || !strcmp(value, "none")) { fault = FAULT_NONE; return true; }
  static const char *names[] = { "none", "setup", "hang", "cleanup", "property" };
  for (size_t index = 1; index < sizeof(names) / sizeof(*names); ++index) {
    if (!strcmp(value, names[index])) {
      fault = (enum fault_mode)index;
      fault_name = names[index];
      return true;
    }
  }
  return false;
}
static bool close_declared(void) {
  bool closed = true;
  if (dup_res >= 0 && close(dup_res)) closed = false;
  if (test_fd >= 0 && test_fd != dup_res) {
    errno = 0;
    if (fcntl(test_fd, F_GETFD) >= 0) {
      if (close(test_fd)) closed = false;
    } else if (errno != EBADF) {
      closed = false;
    }
  }
  return closed;
}
static bool teardown(bool inject_cleanup) {
  bool closed = close_declared();
  int fault_fd = inject_cleanup ? open("/", O_PATH) : -1;
  int actual[MAX_FDS];
  size_t count = 0;
  bool observed = collect_fds(actual, &count);
  bool restored = observed && same_fds(initial_fds, initial_count, actual, count);
  bool passed = closed && restored && !inject_cleanup;
  printf("KCONC_PHASE {\"phase\":\"teardown\",\"passed\":%s,\"resources_closed\":%s,"
         "\"fd_set_restored\":%s,\"fd_snapshot_observed\":%s,\"injected\":%s,"
         "\"fault_resource_fd\":%d,\"expected_fds\":",
         boolean(passed), boolean(closed && fault_fd < 0), boolean(restored),
         boolean(observed), boolean(inject_cleanup), fault_fd);
  print_fds(initial_fds, initial_count);
  printf(",\"actual_fds\":"); print_fds(actual, count);
  printf("}"); flush_phase();
  /* The injected descriptor is deliberately still open at this checkpoint.
   * Child termination will close it; that does not retroactively pass teardown. */
  return passed;
}

void test_setup(void) {
  a_calls = b_calls = 0;
  test_fd = -1; dup_res = -2; dup_errno = 0;
  if (!parse_fault() || !collect_fds(initial_fds, &initial_count)) {
    printf("KCONC_PHASE {\"phase\":\"setup\",\"passed\":false,"
           "\"reason\":\"invalid-fault-or-initial-fd-snapshot-failed\"}");
    flush_phase();
    _exit(65);
  }
  upstream_test_setup();
  bool setup_ok = test_fd >= 0 && fault != FAULT_SETUP;
  printf("KCONC_PHASE {\"phase\":\"setup\",\"passed\":%s,\"fault\":\"%s\","
         "\"injected\":%s,\"fd\":%d,\"initial_fds\":",
         boolean(setup_ok), fault_name, boolean(fault == FAULT_SETUP), test_fd);
  print_fds(initial_fds, initial_count);
  printf("}"); flush_phase();
  if (!setup_ok) {
    (void)teardown(false);
    _exit(71);
  }
  int actual[MAX_FDS], expected[MAX_FDS];
  size_t count = 0;
  bool observed = collect_fds(actual, &count);
  bool valid = fcntl(test_fd, F_GETFD) >= 0;
  int flags = fcntl(test_fd, F_GETFL);
  bool is_path = flags >= 0 && (flags & O_PATH) == O_PATH;
  bool room = initial_count < MAX_FDS;
  size_t expected_count = initial_count;
  memcpy(expected, initial_fds, initial_count * sizeof(*expected));
  if (room) {
    expected[expected_count++] = test_fd;
    qsort(expected, expected_count, sizeof(*expected), compare_fd);
  }
  bool matches = room && observed && same_fds(expected, expected_count, actual, count);
  bool passed = valid && is_path && matches;
  printf("KCONC_PHASE {\"phase\":\"initial_state\",\"passed\":%s,\"fd\":%d,"
         "\"fd_valid\":%s,\"fd_is_path\":%s,\"fd_set_matches\":%s,\"expected_fds\":",
         boolean(passed), test_fd, boolean(valid), boolean(is_path), boolean(matches));
  print_fds(expected, expected_count);
  printf(",\"actual_fds\":"); print_fds(actual, count);
  printf("}"); flush_phase();
  if (!passed) {
    (void)teardown(false);
    _exit(72);
  }
}

void test_thread1(void) {
  ++a_calls;
  if (fault == FAULT_HANG) for (;;) pause();
  upstream_test_thread1();
}
void test_thread2(void) {
  ++b_calls;
  upstream_test_thread2();
}
void test_end(void) {
  bool completed = a_calls == 1 && b_calls == 1;
  printf("KCONC_PHASE {\"phase\":\"operations\",\"passed\":%s,\"a_calls\":%u,\"b_calls\":%u}",
         boolean(completed), a_calls, b_calls);
  flush_phase();
  upstream_test_end();
  bool natural = completed && ((dup_res >= 0 && fcntl(dup_res, F_GETFD) >= 0)
                              || (dup_res == -1 && dup_errno == EBADF));
  bool injected = fault == FAULT_PROPERTY;
  printf("KCONC_PHASE {\"phase\":\"property\",\"passed\":%s,"
         "\"oracle\":\"legal-dup-close-result\",\"natural_passed\":%s,"
         "\"injected\":%s,\"oracle_test_only\":%s,\"outcome\":{\"fd\":%d,\"result\":%d,\"errno\":%d}}",
         boolean(natural && !injected), boolean(natural), boolean(injected), boolean(injected),
         test_fd, dup_res, dup_errno);
  flush_phase();
  if (!teardown(fault == FAULT_CLEANUP) || !completed) _exit(73);
}
