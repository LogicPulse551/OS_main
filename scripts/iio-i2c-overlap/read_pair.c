/* Two ordinary BMA400 IIO sysfs reads in separate threads. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct reader {
    int attrfd, markerfd, cpu, tid, error;
    ssize_t size;
    long value;
    char axis, key[16];
    pthread_barrier_t *start;
};

static void fail(const char *what)
{
    perror(what);
    exit(1);
}

static void thread_check(int code, const char *what)
{
    if (code) {
        errno = code;
        fail(what);
    }
}

static void *read_axis(void *arg)
{
    struct reader *r = arg;
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(r->cpu, &cpus);
    thread_check(pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus), "reader affinity");
    r->tid = (int)syscall(SYS_gettid);
    if (r->start) {
        int rc = pthread_barrier_wait(r->start);
        if (rc != PTHREAD_BARRIER_SERIAL_THREAD)
            thread_check(rc, "reader rendezvous");
    }
    if (dprintf(r->markerfd, "IIO_BEGIN key=%s axis=%c\n", r->key, r->axis) < 0)
        fail("trace begin");
    char data[64] = {0}, *end;
    r->size = pread(r->attrfd, data, sizeof(data) - 1, 0);
    r->error = r->size < 0 ? errno : 0;
    if (r->size > 0) {
        errno = 0;
        r->value = strtol(data, &end, 10);
        if (errno || end == data || strcmp(end, "\n"))
            r->error = EPROTO;
    } else if (!r->error) {
        r->error = EIO;
    }
    if (dprintf(r->markerfd, "IIO_END key=%s axis=%c rc=%d value=%ld\n",
                r->key, r->axis, -r->error, r->value) < 0)
        fail("trace end");
    return NULL;
}

static long long now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts))
        fail("monotonic clock");
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

static void read_state(int params, char *buf, size_t size)
{
    int fd = openat(params, "replay_state", O_RDONLY);
    if (fd < 0)
        fail("open replay_state");
    ssize_t n = read(fd, buf, size - 1);
    if (n <= 0 || (size_t)n >= size-1 || buf[n-1] != '\n')
        fail("replay_state");
    buf[n] = 0;
    close(fd);
}

static int active_pair(struct reader *ops, const char *mode, const char *param_path)
{
    int owner = mode[7] == 'X' ? 0 : 1;
    int peer = 1 - owner;
    int params = open(param_path, O_RDONLY | O_DIRECTORY);
    FILE *receipt = fopen("control.txt", "wx");
    if (params < 0 || !receipt)
        fail("open peripheral controls");
    char state[512];
    read_state(params, state, sizeof(state));
    fprintf(receipt, "before %s", state);
    fflush(receipt);
    if (strncmp(state, "phase=idle ", 11))
        return 1;
    int arm = openat(params, "replay_arm", O_WRONLY);
    const char *reg = owner == 0 ? "4\n" : "6\n";
    if (arm < 0 || write(arm, reg, 2) != 2)
        fail("arm virtual peripheral");
    close(arm);
    read_state(params, state, sizeof(state));
    fprintf(receipt, "armed %s", state);
    fflush(receipt);
    if (strncmp(state, "phase=armed ", 12))
        return 1;
    pthread_t first, second;
    thread_check(pthread_create(&first, NULL, read_axis, &ops[owner]), "start owner");
    long long deadline = now_ms() + 3000;
    int started = 0;
    do {
        read_state(params, state, sizeof(state));
        if (!strncmp(state, "phase=pending ", 14)) {
            fprintf(receipt, "seen %s", state);
            fflush(receipt);
            thread_check(pthread_create(&second, NULL, read_axis, &ops[peer]), "start companion");
            started = 1;
            break;
        }
        if (!strncmp(state, "phase=done ", 11))
            break;
        sched_yield();
    } while (now_ms() < deadline);
    if (started)
        thread_check(pthread_join(second, NULL), "join companion");
    thread_check(pthread_join(first, NULL), "join owner");
    read_state(params, state, sizeof(state));
    fprintf(receipt, "after %s", state);
    fclose(receipt);
    close(params);
    return !started || strncmp(state, "phase=done ", 11);
}

int main(int argc, char **argv)
{
    if (argc != 4 || (strcmp(argv[2],"natural") && strcmp(argv[2],"active-X") && strcmp(argv[2],"active-Y")))
        return 2;
    int natural = !strcmp(argv[2],"natural");
    int device = open(argv[1], O_RDONLY | O_DIRECTORY);
    int marker = open("/sys/kernel/tracing/trace_marker", O_WRONLY);
    const char *attributes[] = {"in_accel_x_raw", "in_accel_y_raw"};
    int attrs[] = {openat(device, attributes[0], O_RDONLY), openat(device, attributes[1], O_RDONLY)};
    if (device < 0 || marker < 0 || attrs[0] < 0 || attrs[1] < 0)
        fail("open native IIO axes");
    cpu_set_t available;
    if (sched_getaffinity(0, sizeof(available), &available))
        fail("guest cpu affinity");
    int cpu[2], ncpu = 0;
    for (int i=0; i<CPU_SETSIZE && ncpu<2; ++i)
        if (CPU_ISSET(i, &available))
            cpu[ncpu++] = i;
    if (ncpu != 2)
        return 2;
    pthread_barrier_t rendezvous;
    if (natural)
        thread_check(pthread_barrier_init(&rendezvous, NULL, 2), "create rendezvous");
    for (int g=1; g<=(natural ? 96 : 1); ++g) {
        struct reader ops[2] = {0};
        for (int i=0; i<2; ++i) {
            ops[i].axis = i ? 'Y' : 'X';
            ops[i].attrfd = attrs[i];
            ops[i].markerfd = marker;
            ops[i].cpu = cpu[i];
            ops[i].start = natural ? &rendezvous : NULL;
            snprintf(ops[i].key, sizeof(ops[i].key), "g%03d%c", g, i ? 'y' : 'x');
        }
        int error = 0;
        if (natural) {
            pthread_t threads[2];
            /* Alternate creation order without ordering driver calls. */
            for (int j=0; j<2; ++j) {
                int i = (j + (g-1)%2)%2;
                thread_check(pthread_create(&threads[i], NULL, read_axis, &ops[i]), "start reader");
            }
            for (int i=0; i<2; ++i)
                thread_check(pthread_join(threads[i], NULL), "join reader");
        } else {
            error = active_pair(ops, argv[2], argv[3]);
        }
        for (int i=0; i<2; ++i) {
            printf("%s\t%c\t%d\t%zd\t%d\t%ld\n", ops[i].key, ops[i].axis, ops[i].tid,
                   ops[i].size, ops[i].error, ops[i].value);
            if (ops[i].error || ops[i].size <= 0)
                error = 1;
        }
        fflush(stdout);
        if (error)
            return 1;
    }
    if (natural)
        thread_check(pthread_barrier_destroy(&rendezvous), "destroy rendezvous");
    close(attrs[0]);
    close(attrs[1]);
    close(marker);
    close(device);
    return 0;
}
