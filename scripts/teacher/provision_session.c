/* Install a fresh SSH public key into a disposable guest overlay. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <unistd.h>

static void fail(const char *at)
{
	perror(at);
	sync();
	reboot(RB_POWER_OFF);
	_exit(1);
}

static void prepare_account(void)
{
	const char *script = "/payload/provision-account.sh";
	int job, status;
	if (access(script, F_OK))
		return;
	if (mount("/dev", "/sysroot/dev", NULL, MS_BIND, NULL) ||
	    mount("proc", "/sysroot/proc", "proc", MS_NOSUID | MS_NODEV, NULL))
		fail("account setup mounts");
	job = fork();
	if (job == 0) {
		int input = open(script, O_RDONLY);
		if (input < 0 || dup2(input, STDIN_FILENO) < 0 || chroot("/sysroot") || chdir("/"))
			_exit(125);
		execl("/bin/bash", "bash", "-seu", (char *)NULL);
		_exit(126);
	}
	if (job < 0 || waitpid(job, &status, 0) != job || !WIFEXITED(status) || WEXITSTATUS(status))
		fail("temporary guest account setup");
	if (umount("/sysroot/proc") || umount("/sysroot/dev"))
		fail("account setup unmounts");
	dprintf(STDOUT_FILENO, "TEACHER_NEW_ACCOUNT_PREPARED\n");
}

int main(void)
{
	char key[1024], check[1024];
	ssize_t size;
	int fd, src, target;

	if (mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, NULL))
		fail("devtmpfs");
	fd = open("/dev/console", O_RDWR);
	if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0)
		fail("console");
	for (int i = 0; i < 100 && access("/dev/vda2", F_OK); i++)
		usleep(100000);
	if (mount("/dev/vda2", "/sysroot", "ext4", MS_NOSUID | MS_NODEV, NULL))
		fail("temporary root");
	prepare_account();
	src = open("/payload/session.pub", O_RDONLY);
	if (src < 0 || (size = read(src, key, sizeof(key))) < 16 ||
	    size >= (ssize_t)sizeof(key) || memcmp(key, "ssh-ed25519 ", 12) || key[size - 1] != '\n')
		fail("session public key");
	close(src);
	/* Keep ownership, SELinux attributes and mode of the existing account's
	 * key file. The backing image is never attached to this VM for writing. */
	target = open("/sysroot/home/lab/.ssh/authorized_keys", O_RDWR | O_TRUNC | O_NOFOLLOW);
	if (target < 0 || write(target, key, size) != size || fsync(target) ||
	    lseek(target, 0, SEEK_SET) < 0 || read(target, check, sizeof(check)) != size ||
	    memcmp(key, check, size))
		fail("install session public key");
	if (close(target) || umount("/sysroot"))
		fail("close temporary root");
	dprintf(STDOUT_FILENO, "TEACHER_SESSION_KEY_INSTALLED\n");
	sync();
	reboot(RB_POWER_OFF);
	return 1;
}
