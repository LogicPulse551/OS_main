// SPDX-License-Identifier: GPL-2.0-only
/* Run in the small initramfs, during the real map's active lifetime. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static int content(const char *path, const char *wanted)
{
	char data[200];
	int fd = open(path, O_RDONLY);
	ssize_t len;

	if (fd < 0)
		return 0;
	len = read(fd, data, sizeof(data) - 1);
	close(fd);
	if (len < 0)
		return 0;
	data[len] = 0;
	return strstr(data, wanted) != NULL;
}

int main(int argc, char **argv)
{
	struct stat st;
	int hidden;

	if (argc != 2 || (strcmp(argv[1], "hidden") && strcmp(argv[1], "visible")))
		return 1;
	hidden = !strcmp(argv[1], "hidden");
	alarm(5);
	if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
		return 2;
	if (mount("debugfs", "/c06-debug", "debugfs", MS_RDONLY | MS_NOSUID | MS_NODEV, NULL))
		return 3;
	if (chdir("/c06-debug/regmap"))
		return 4;
	if (!content("dummy-c06-control/name", "nodev\n") || !content("dummy-c06-control/registers", "0: 5a"))
		return 5;
	if (hidden)
		return stat("dummy-c02-bulk", &st) == -1 && errno == ENOENT ? 0 : 6;
	if (!content("dummy-c02-bulk/name", "nodev\n") || stat("dummy-c02-bulk/registers", &st) ||
	    !S_ISREG(st.st_mode) || !(st.st_mode & S_IRUSR))
		return 7;
	return 0;
}
