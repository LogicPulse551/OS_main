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
#include <unistd.h>

/* The registered kernel's extended KCOV UAPI uses mode 3. No control ioctls. */
enum { memory_trace = 3, trace_words = 131072 };
struct operation {
    const char *device;
    const char *key;
    char axis;
    pthread_barrier_t *start;
};

static void fail(const char *message)
{
    perror(message);
    exit(1);
}

static void *read_axis(void *argument)
{
    struct operation *op = argument;
    char path[512], data[128] = {0}, *end;
    int tid = (int)syscall(SYS_gettid);
    snprintf(path, sizeof(path), "%s/in_accel_%c_raw", op->device, tolower(op->axis));
    int axis_fd = open(path, O_RDONLY);
    int marker = open("/sys/kernel/tracing/trace_marker", O_WRONLY);
    int event_fd = open("/sys/kernel/debug/kcov", O_RDWR);
    if (axis_fd < 0 || marker < 0 || event_fd < 0) fail("open read endpoint");
    if (ioctl(event_fd, KCOV_INIT_TRACE, trace_words)) fail("KCOV_INIT_TRACE");
    unsigned long *words = mmap(NULL, trace_words * sizeof(*words), PROT_READ | PROT_WRITE,
                                MAP_SHARED, event_fd, 0);
    if (words == MAP_FAILED) fail("mmap trace");
    if (op->start) pthread_barrier_wait(op->start);
    if (dprintf(marker, "IIO_BEGIN key=%s axis=%c\n", op->key, op->axis) <= 0) fail("begin");
    if (ioctl(event_fd, KCOV_ENABLE, memory_trace)) fail("KCOV_ENABLE");
    __atomic_store_n(words, 0, __ATOMIC_RELAXED);
    ssize_t size = pread(axis_fd, data, sizeof(data) - 1, 0);
    int saved_errno = size < 0 ? errno : 0;
    unsigned long count = __atomic_load_n(words, __ATOMIC_RELAXED);
    if (ioctl(event_fd, KCOV_DISABLE, 0)) fail("KCOV_DISABLE");
    long value = strtol(data, &end, 10);
    if (dprintf(marker, "IIO_END key=%s axis=%c rc=%d value=%ld\n",
                op->key, op->axis, saved_errno ? -saved_errno : 0, value) <= 0) fail("end");
    if (size <= 0 || end == data || (*end && strcmp(end, "\n")) || !count || count >= trace_words - 5) {
        fprintf(stderr, "invalid read/trace key=%s size=%zd errno=%d words=%lu\n",
                op->key, size, saved_errno, count);
        exit(2);
    }
    snprintf(path, sizeof(path), "%s.words", op->key);
    FILE *out = fopen(path, "wbx");
    if (!out || fwrite(words + 1, sizeof(*words), count, out) != count || fclose(out)) fail("save words");
    printf("%s\t%c\t%d\t%zd\t%d\t%ld\t%lu\n", op->key, op->axis, tid, size,
           saved_errno, value, count);
    munmap(words, trace_words * sizeof(*words));
    close(axis_fd);
    close(marker);
    close(event_fd);
    return NULL;
}

/* Sequential readers finish one at a time. Parallel readers meet at one
 * barrier before entering sysfs; the kernel decides their subsequent order. */
int main(int argc, char **argv)
{
    if ((argc != 7 && argc != 9) || (strcmp(argv[2], "seq") && strcmp(argv[2], "parallel"))) return 2;
    int count = (argc - 3) / 2;
    pthread_barrier_t barrier;
    int parallel = !strcmp(argv[2], "parallel");
    if (parallel && pthread_barrier_init(&barrier, NULL, count)) return 1;
    pthread_t threads[3];
    struct operation operations[3];
    for (int i = 0; i < count; i++) {
        const char *axis = argv[4 + 2*i];
        if (strlen(axis) != 1 || !strchr("XYZ", *axis)) return 2;
        operations[i] = (struct operation){argv[1], argv[3 + 2*i], *axis, parallel ? &barrier : NULL};
        if (pthread_create(&threads[i], NULL, read_axis, &operations[i])) return 1;
        if (!parallel && pthread_join(threads[i], NULL)) return 1;
    }
    if (parallel) {
        for (int i = 0; i < count; i++)
            if (pthread_join(threads[i], NULL)) return 1;
        pthread_barrier_destroy(&barrier);
    }
    return 0;
}
