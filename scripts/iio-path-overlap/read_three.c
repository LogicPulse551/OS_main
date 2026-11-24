/* Normal X/Y/Z sysfs reads, with one preparation window on the software board. */
#define _GNU_SOURCE
#include <ctype.h>
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
    char attribute[32];
    snprintf(attribute, sizeof(attribute), "in_accel_%c_raw", tolower((unsigned char)*axis));
    int attr = openat(dir, attribute, O_RDONLY);
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

static int launch(pthread_t *thread, struct reader *op)
{
    int error = pthread_create(thread, NULL, read_one, op);
    if (error)
        fprintf(stderr, "create %s reader: %s\n", op->axis, strerror(error));
    return !error;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: read-axes IIO_DEVICE BOARD_PARAMETER_DIRECTORY\n");
        return 2;
    }
    struct reader readers[] = {
        {argv[1], "X", "x3", -1, -1},
        {argv[1], "Y", "y3", -1, -1},
        {argv[1], "Z", "z3", -1, -1}
    };
    const int params = open(argv[2], O_RDONLY | O_DIRECTORY);
    if (params < 0) die("open board parameters");
    FILE *receipt = fopen("control.tsv", "wx");
    if (!receipt) die("control.tsv");
    fprintf(receipt, "x_key\tx_tid\tx_exit\ty_key\ty_tid\ty_exit\tz_key\tz_tid\tz_exit\t"
            "callback_tid\tstate_before\tstate_armed\tstate_observed\tstate_after\t"
            "arm_ns\twarming_seen_ns\ty_state\ty_started_ns\tz_state\tz_started_ns\tjoined_ns\n");
    fflush(receipt);
    int before = read_parameter(params, "window_state");
    int armed = -1, observed = -1, callback_tid = -1, launch_state[3] = {-1, -1, -1};
    long long arm_ns = 0, seen_ns = 0, launch_ns[3] = {0};
    pthread_t threads[3];
    int started[3] = {0};
    if (before == 0) {
        arm_ns = monotonic_ns();
        int fd = openat(params, "window_arm", O_WRONLY);
        if (fd < 0 || write(fd, "1\n", 2) != 2) die("arm board");
        close(fd);
        armed = read_parameter(params, "window_state");
    }
    if (armed == 1)
        started[0] = launch(&threads[0], &readers[0]);

    /* Only the board waits. The driver and its locks follow their normal path. */
    while (started[0] && monotonic_ns() - arm_ns < 2000000000LL) {
        observed = read_parameter(params, "window_state");
        if (observed == 2) {
            seen_ns = monotonic_ns();
            callback_tid = read_parameter(params, "window_tid");
            for (int i = 1; i < 3; ++i) {
                launch_state[i] = read_parameter(params, "window_state");
                if (launch_state[i] != 2) break;
                launch_ns[i] = monotonic_ns();
                started[i] = launch(&threads[i], &readers[i]);
            }
            break;
        }
        if (observed == 3) break;
        struct timespec wait = {.tv_nsec = 250000};
        nanosleep(&wait, NULL);
    }
    for (int i = 0; i < 3; ++i) {
        if (started[i]) {
            int error = pthread_join(threads[i], NULL);
            if (error) {
                errno = error;
                die("join reader");
            }
        }
    }
    long long joined_ns = monotonic_ns();
    int after = read_parameter(params, "window_state");
    for (int i = 0; i < 3; ++i)
        fprintf(receipt, "%s\t%d\t%d\t", readers[i].key, readers[i].tid, readers[i].status);
    fprintf(receipt, "%d\t%d\t%d\t%d\t%d\t%lld\t%lld\t%d\t%lld\t%d\t%lld\t%lld\n",
            callback_tid, before, armed, observed, after, arm_ns, seen_ns,
            launch_state[1], launch_ns[1], launch_state[2], launch_ns[2], joined_ns);
    if (fclose(receipt)) die("finish control.tsv");
    close(params);
    return !(observed == 2 && after == 3 && callback_tid == readers[0].tid &&
             !readers[0].status && !readers[1].status && !readers[2].status);
}
