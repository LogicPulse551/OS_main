/* Capture one public IIO axis read in its issuing task. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kcov.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

enum { trace_words = 131072, extended_memory_trace = 3 };

static void die(const char *reason)
{
    perror(reason);
    exit(1);
}

struct reader {
    const char *device;
    const char *axis;
    const char *key;
    int tid;
    int status;
};

static void *read_one(void *argument)
{
    struct reader *op = argument;
    const char *axis = op->axis, *key = op->key;
    int dir = open(op->device, O_DIRECTORY | O_RDONLY);
    int attr = openat(dir, *axis == 'X' ? "in_accel_x_raw" : "in_accel_y_raw", O_RDONLY);
    int trace = open("/sys/kernel/debug/kcov", O_RDWR);
    int marker = open("/sys/kernel/tracing/trace_marker", O_WRONLY);
    if (dir < 0 || attr < 0 || trace < 0 || marker < 0) die("open read endpoints");
    if (ioctl(trace, KCOV_INIT_TRACE, trace_words)) die("reserve coverage buffer");
    unsigned long *records = mmap(NULL, trace_words * sizeof(*records), PROT_READ | PROT_WRITE,
                                  MAP_SHARED, trace, 0);
    if (records == MAP_FAILED) die("map coverage buffer");
    const int tid = (int)syscall(SYS_gettid);
    op->tid = tid;
    char data[128] = {0};
    if (dprintf(marker, "IIO_BEGIN key=%s axis=%s\n", key, axis) < 0) die("begin marker");
    if (ioctl(trace, KCOV_ENABLE, extended_memory_trace)) die("start coverage");
    __atomic_store_n(records, 0, __ATOMIC_RELAXED);
    ssize_t size = pread(attr, data, sizeof(data) - 1, 0);
    int error = size < 0 ? errno : 0;
    unsigned long count = __atomic_load_n(records, __ATOMIC_RELAXED);
    if (ioctl(trace, KCOV_DISABLE, 0)) die("stop coverage");
    errno = 0;
    char *end;
    long value = strtol(data, &end, 10);
    int parsed = !errno && end != data && (*end == '\0' || !strcmp(end, "\n"));
    if (dprintf(marker, "IIO_END key=%s axis=%s rc=%d value=%ld\n", key, axis, -error, value) < 0)
        die("end marker");
    printf("%s\t%s\t%d\t%zd\t%d\t%ld\t%lu\n", key, axis, tid, size, error, value, count);
    if (count > 0 && count < trace_words - 5) {
        char name[48];
        snprintf(name, sizeof(name), "%s.words", key);
        FILE *out = fopen(name, "wbx");
        if (!out || fwrite(records + 1, sizeof(*records), count, out) != count || fclose(out)) die("save coverage");
        op->status = size > 0 && parsed ? 0 : 1;
    }
    munmap(records, trace_words * sizeof(*records));
    close(marker);
    close(trace);
    close(attr);
    close(dir);
    return NULL;
}

static long long monotonic_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) die("clock_gettime");
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int read_parameter(int base, const char *name)
{
    int fd = openat(base, name, O_RDONLY);
    if (fd < 0) die(name);
    char data[48] = {0}, *end;
    if (read(fd, data, sizeof(data) - 1) <= 0) die(name);
    close(fd);
    long n = strtol(data, &end, 10);
    if (end == data || (*end != '\n' && *end) || n < 0 || n > 2147483647) {
        fprintf(stderr, "invalid board parameter %s: %s\n", name, data);
        exit(1);
    }
    return (int)n;
}

int main(int argc, char **argv)
{
    if (argc != 4 || (strcmp(argv[3], "XY") && strcmp(argv[3], "YX"))) {
        fprintf(stderr, "usage: read-axes IIO_DEVICE BOARD_PARAMETER_DIRECTORY XY|YX\n");
        return 2;
    }
    struct reader x = {argv[1], "X", "x1", -1, -1}, y = {argv[1], "Y", "y1", -1, -1};
    struct reader *owner = *argv[3] == 'X' ? &x : &y;
    struct reader *peer = *argv[3] == 'X' ? &y : &x;
    int params = open(argv[2], O_RDONLY | O_DIRECTORY);
    if (params < 0) die("open board parameters");
    FILE *receipt = fopen("control.tsv", "wx");
    if (!receipt) die("control.tsv");
    fprintf(receipt, "owner_key\towner_axis\towner_tid\tpeer_key\tpeer_axis\tpeer_tid\tcallback_tid\t"
            "state_before\tstate_armed\tstate_observed\tstate_after\tarm_ns\twarming_seen_ns\t"
            "peer_started_ns\tjoined_ns\towner_exit\tpeer_exit\n");
    fflush(receipt);
    int initial = read_parameter(params, "window_state");
    if (initial != 0) {
        fprintf(stderr, "expected unused board, state=%d\n", initial);
        return 1;
    }
    long long arm_ns = monotonic_ns();
    int arm_fd = openat(params, "window_arm", O_WRONLY);
    if (arm_fd < 0 || write(arm_fd, "1\n", 2) != 2) die("window_arm");
    close(arm_fd);
    int armed = read_parameter(params, "window_state");
    if (armed != 1) {
        fprintf(stderr, "board did not arm, state=%d\n", armed);
        return 1;
    }
    pthread_t first, second;
    if (pthread_create(&first, NULL, read_one, owner)) die("first thread");
    long long warming = 0, peer_start = 0;
    int observed = -1, callback_tid = -1;
    long long deadline = arm_ns + 2000000000LL;
    while (monotonic_ns() < deadline) {
        observed = read_parameter(params, "window_state");
        if (observed == 2) {
            warming = monotonic_ns();
            callback_tid = read_parameter(params, "window_tid");
            peer_start = monotonic_ns();
            if (pthread_create(&second, NULL, read_one, peer)) die("second thread");
            break;
        }
        if (observed == 3) break;
        struct timespec delay = {.tv_nsec = 250000};
        nanosleep(&delay, NULL);
    }
    if (pthread_join(first, NULL) || (peer_start && pthread_join(second, NULL))) die("join readers");
    long long joined = monotonic_ns();
    int final = read_parameter(params, "window_state");
    fprintf(receipt, "%s\t%s\t%d\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%lld\t%lld\t%lld\t%lld\t%d\t%d\n",
            owner->key, owner->axis, owner->tid, peer->key, peer->axis, peer->tid, callback_tid,
            initial, armed, observed, final, arm_ns, warming, peer_start, joined, owner->status, peer->status);
    if (fclose(receipt)) die("finish control.tsv");
    close(params);
    return !(observed == 2 && final == 3 && callback_tid > 0 && !owner->status && !peer->status);
}
