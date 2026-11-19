/* K02 runtime smoke probe. Compile with -I <locked MAccConc source root>. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <gnu/libc-version.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "third_party/kcov.h"

enum { BUFFER_WORDS = 1 << 20 };

static int fail(const char *stage) {
  int saved = errno;
  fprintf(stderr, "%s: %s\n", stage, strerror(saved));
  printf("{\"passed\":false,\"stage\":\"%s\",\"errno\":%d}\n", stage, saved);
  return 1;
}

static void json_string(const char *value) {
  putchar('"');
  for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
    if (*p == '"' || *p == '\\') printf("\\%c", *p);
    else if (*p < 32) printf("\\u%04x", *p);
    else putchar(*p);
  }
  putchar('"');
}

static int layout_ok(void) {
  return sizeof(unsigned long) == 8 && sizeof(void *) == 8 &&
      sizeof(struct memory_access_record) == 40 &&
      sizeof(struct kcov_di_stack) == 24 && sizeof(struct kcov_set_di_arg) == 24;
}

static void print_abi(void) {
  struct utsname uts;
  if (uname(&uts)) memset(&uts, 0, sizeof(uts));
  printf("\"abi\":{\"unsigned_long\":%zu,\"pointer\":%zu,"
         "\"memory_access_record\":%zu,\"kcov_di_stack\":%zu,"
         "\"kcov_set_di_arg\":%zu,\"stdc_version\":%ld,\"compiler\":",
         sizeof(unsigned long), sizeof(void *), sizeof(struct memory_access_record),
         sizeof(struct kcov_di_stack), sizeof(struct kcov_set_di_arg),
         (long)__STDC_VERSION__);
  json_string(__VERSION__);
  printf(",\"glibc_runtime\":"); json_string(gnu_get_libc_version());
  printf(",\"machine\":"); json_string(uts.machine);
  printf(",\"kernel\":"); json_string(uts.release);
  printf("}");
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--abi-only") == 0) {
    printf("{\"passed\":%s,\"scope\":\"userspace-layout-only\",", layout_ok() ? "true" : "false");
    print_abi(); puts("}");
    return layout_ok() ? 0 : 1;
  }
  if (argc > 2) {
    fprintf(stderr, "usage: %s [--abi-only | /sys/kernel/debug/kcov]\n", argv[0]);
    return 2;
  }
  if (!layout_ok()) { errno = EPROTO; return fail("userspace-layout"); }
  if (geteuid() != 0) { errno = EPERM; return fail("requires-root"); }
  const char *device = argc == 2 ? argv[1] : "/sys/kernel/debug/kcov";
  int fd = open(device, O_RDWR | O_CLOEXEC);
  if (fd < 0) return fail("open-kcov");
  int record_bytes = ioctl(fd, KCOV_GET_MEMORY_RECORD_SIZE, 0);
  if (record_bytes < 0) { int saved = errno; close(fd); errno = saved; return fail("query-memory-record-size"); }
  if (record_bytes != (int)sizeof(struct memory_access_record)) {
    fprintf(stderr, "kernel record size %d, expected %zu\n", record_bytes, sizeof(struct memory_access_record));
    close(fd); errno = EPROTO; return fail("kernel-record-layout");
  }
  if (ioctl(fd, KCOV_INIT_TRACE, (unsigned long)BUFFER_WORDS)) {
    int saved = errno; close(fd); errno = saved; return fail("init-trace");
  }
  size_t map_bytes = BUFFER_WORDS * sizeof(unsigned long);
  unsigned long *area = mmap(NULL, map_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (area == MAP_FAILED) { int saved = errno; close(fd); errno = saved; return fail("mmap-trace"); }
  int nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
  if (nullfd < 0) { int saved = errno; munmap(area, map_bytes); close(fd); errno = saved; return fail("open-workload"); }
  if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_MEMORY_ACCESS)) {
    int saved = errno; close(nullfd); munmap(area, map_bytes); close(fd); errno = saved;
    return fail("enable-memory-trace");
  }
  __atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
  struct stat metadata;
  int workload_failed = 0;
  for (int i = 0; i < 4; ++i) {
    if (syscall(SYS_getpid) < 0 || syscall(SYS_fstat, nullfd, &metadata) < 0)
      workload_failed = 1;
  }
  /* Capture the measurement boundary before the disable ioctl adds its own records. */
  unsigned long words = __atomic_load_n(&area[0], __ATOMIC_RELAXED);
  if (ioctl(fd, KCOV_DISABLE, 0)) {
    int saved = errno; close(nullfd); munmap(area, map_bytes); close(fd); errno = saved;
    return fail("disable-trace");
  }
  unsigned long events = 0, memories = 0, entries = 0, exits = 0, reads = 0, writes = 0, frees = 0;
  int malformed = words >= BUFFER_WORDS;
  for (unsigned long offset = 1; !malformed && offset <= words;) {
    unsigned long type = area[offset] & KCOV_RECORDFLAG_TYPEMASK;
    unsigned long length = 1;
    switch (type) {
      case KCOV_RECORDFLAG_TYPE_ENTRY: length = 2; entries++; break;
      case KCOV_RECORDFLAG_TYPE_MEMORY: length = (unsigned long)record_bytes / sizeof(unsigned long); break;
      case KCOV_RECORDFLAG_TYPE_EXIT: exits++; break;
      case KCOV_RECORDFLAG_TYPE_NORMAL:
      case KCOV_RECORDFLAG_TYPE_EESUM:
      case KCOV_RECORDFLAG_TYPE_WAIT:
      case KCOV_RECORDFLAG_TYPE_WAKE: break;
      default: malformed = 1;
    }
    if (malformed || length > words - offset + 1) { malformed = 1; break; }
    if (type == KCOV_RECORDFLAG_TYPE_MEMORY) {
      struct memory_access_record record;
      memcpy(&record, &area[offset], sizeof(record));
      memories++;
      if (record.flags & MEMORY_ACCESS_RECORD_FREE) frees++;
      else if (record.flags & (MEMORY_ACCESS_RECORD_WRITE | MEMORY_ACCESS_RECORD_RMW)) writes++;
      else reads++;
    }
    events++;
    offset += length;
  }
  int near_capacity = words >= BUFFER_WORDS - (unsigned long)record_bytes / sizeof(unsigned long) - 1;
  int passed = !workload_failed && !malformed && !near_capacity && events > 0 && memories > 0 && entries > 0 && exits > 0;
  printf("{\"passed\":%s,\"scope\":\"single-thread-kcov-runtime-smoke\",", passed ? "true" : "false");
  print_abi();
  printf(",\"kernel_record_bytes\":%d,\"buffer_words\":%u,\"captured_words\":%lu,"
         "\"events\":%lu,\"memory_records\":%lu,\"entries\":%lu,\"exits\":%lu,"
         "\"read_only\":%lu,\"writes_or_rmw\":%lu,\"frees\":%lu,\"malformed\":%s,\"buffer_near_capacity\":%s,\"workload_failed\":%s}\n",
         record_bytes, BUFFER_WORDS, words, events, memories, entries, exits, reads, writes, frees,
         malformed ? "true" : "false", near_capacity ? "true" : "false", workload_failed ? "true" : "false");
  close(nullfd); munmap(area, map_bytes); close(fd);
  return passed ? 0 : 1;
}
