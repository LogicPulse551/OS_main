/* Run the IIO reader against a read-only root with a private runtime directory. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static void stop(const char *point)
{
	perror(point);
	dprintf(STDOUT_FILENO, "IIO_EARLY_FAILURE %s\n", point);
	reboot(RB_POWER_OFF);
	_exit(1);
}

static void mount_at(const char *source, const char *dest, const char *type,
		     unsigned long flags, const char *options)
{
	if (mount(source, dest, type, flags, options))
		stop(dest);
}

int main(void)
{
	int status, i;
	pid_t child;

	mount_at("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, NULL);
	int fd = open("/dev/console", O_RDWR);
	if (fd < 0)
		stop("console");
	for (i = 0; i < 3; ++i)
		if (dup2(fd, i) < 0)
			stop("dup console");
	if (fd > 2)
		close(fd);
	for (i = 0; i < 100 && access("/dev/vda2", F_OK); ++i)
		usleep(100000);
	mount_at("/dev/vda2", "/sysroot", "ext4", MS_RDONLY, "noload");
	mount_at("/dev", "/sysroot/dev", NULL, MS_BIND, NULL);
	mount_at("proc", "/sysroot/proc", "proc", MS_NOSUID | MS_NODEV, NULL);
	mount_at("sysfs", "/sysroot/sys", "sysfs", MS_NOSUID | MS_NODEV, NULL);
	mount_at("tmpfs", "/sysroot/run", "tmpfs", MS_NOSUID | MS_NODEV, "size=16m");
	if (mkdir("/sysroot/run/iio", 0755) < 0)
		stop("run directory");
	mount_at("/payload", "/sysroot/run/iio", NULL, MS_BIND, NULL);
	child = fork();
	if (child < 0)
		stop("fork");
	if (!child) {
		if (chroot("/sysroot") || chdir("/"))
			stop("openEuler root");
		setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
		execl("/bin/bash", "bash", "/run/iio/observe.sh", (char *)NULL);
		stop("openEuler bash");
	}
	if (waitpid(child, &status, 0) != child)
		stop("wait");
	dprintf(STDOUT_FILENO, "IIO_SUPERVISOR_EXIT %d\n", WIFEXITED(status) ? WEXITSTATUS(status) : 1);
	/* Finish the serial status line before the kernel prints its shutdown message. */
	while (tcdrain(STDOUT_FILENO) < 0 && errno == EINTR) {}
	reboot(RB_POWER_OFF);
	return 1;
}
