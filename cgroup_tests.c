/*
 *
 *  cgroup tests - cgroup_tests
 *
 *  Copyright (C) 2014  BMW Car IT GmbH.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

/* A very simple cgroup test program which tortures the cgroup
 * filesystem a bit. Initially it creates a 'random' directory tree
 * and places a memory_hog (or any other program) to a cgroup. After
 * that it moves them around and removes/creates new cgroups at random
 * places.  For each child which dies a new one is created.
 *
 * The implementation is not really optimized for speed.
 *
 * struct cgroup_node represents a cgroup in the filesystem and struct
 * proc_node represents a child. The data structures are connected via
 * list container.
 */

#define _GNU_SOURCE
#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <ftw.h>
#include <libgen.h>
#include <dirent.h>
#include <stdarg.h>
#include <sys/time.h>
#include <signal.h>

#include "list.h"

#define CGROUP_DEFAULT_PATH "/sys/fs/cgroup/memory"
#define UP_ONE "\033[1A"
#define DOWN_ONE "\033[1B"

#define DBG(fmt, arg...) do { \
	if (debug_enabled) \
		printf("%s() " fmt "\n", __FUNCTION__ , ## arg); \
} while (0)

static char *cgroup_path;
static int debug_enabled;
static unsigned int max_siblings = 5;
static unsigned int max_cgroups = 100;
static unsigned int max_children = 50;
static unsigned int nr_children;
static unsigned int nr_cgroups;
static unsigned int cgroup_id;
static char **child_argv;
static int terminate;

struct stats {
	unsigned int mkdir;
	unsigned int rmdir;
	unsigned int moved;
	unsigned int forked;
	unsigned int reaped;
} stats = { 0, };

struct proc_node {
	struct list_head list;
	pid_t pid;
};

struct cgroup_node {
	struct list_head list;
	struct list_head siblings;
	char *path;
	struct list_head procs;
};

static void signal_handler(int sig)
{
	if (terminate)
		exit(EXIT_SUCCESS);
	terminate = 1;
}

static void log_error(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

#define handle_err_en(en, fmt, arg...)					\
        do {								\
		errno = en;						\
		log_error("ERROR: %s: " fmt "\n", strerror(errno), ## arg); \
		exit(EXIT_FAILURE);					\
	} while (0)

#define handle_err(fmt, arg...)						\
        do {								\
		log_error("ERROR: %s: " fmt "\n", strerror(errno), ## arg); \
		exit(EXIT_FAILURE);					\
	} while (0)


static int proc_iterate(struct cgroup_node *cgroup,
				int (*fn)(struct cgroup_node *,
					struct proc_node *))
{
	struct cgroup_node *cgp;
	struct proc_node *proc;

	list_for_each_entry(proc, &cgroup->procs, list) {
		if (!(*fn)(cgroup, proc))
			return 0;
	}

	list_for_each_entry(cgp, &cgroup->siblings, list) {
		if (!proc_iterate(cgp, fn))
			return 0;
	}

	return 1;
}

static int cgroup_iterate(struct cgroup_node *cgroup,
				int (*fn)(struct cgroup_node *))
{
	struct cgroup_node *cgp;

	if (!(*fn)(cgroup))
		return 0;

	list_for_each_entry(cgp, &cgroup->siblings, list) {
		if (!cgroup_iterate(cgp, fn))
			return 0;
	}

	return 1;
}

static void destroy_cgroup(struct cgroup_node *cgroup)
{
	free(cgroup->path);
	free(cgroup);
}

/* Create meta data for managing the cgroups. */
static struct cgroup_node *create_cgroup(const char *basepath, const char *name)
{
	struct cgroup_node *cgp;
	long len;

	cgp= malloc(sizeof(*cgp));
	if (!cgp)
		handle_err("malloc");

	memset(cgp, 0, sizeof(*cgp));

	INIT_LIST_HEAD(&cgp->list);
	INIT_LIST_HEAD(&cgp->siblings);
	INIT_LIST_HEAD(&cgp->procs);

	if (asprintf(&cgp->path, "%s/%s", basepath, name) < 0)
		handle_err("asprintf");

	len = pathconf(cgroup_path, _PC_PATH_MAX);
	if (len < 0)
		handle_err("pathconf");

	if (strlen(cgp->path) + sizeof("/tasks") - 1 > len) {
		DBG("path too long");
		destroy_cgroup(cgp);
		return NULL;
	}

	return cgp;
}

static int add_proc_to_cgroup(struct cgroup_node *cgroup,
					struct proc_node *proc)
{
	char *file, *buf;
	size_t len;
	ssize_t n;
	int fd;

	DBG("%s %ld", cgroup->path, (long int)proc->pid);

	if (asprintf(&file, "%s/tasks", cgroup->path) < 0)
		handle_err("asprintf");

	fd = open(file, O_APPEND | O_WRONLY, S_IWUSR);
	if (fd < 0)
		handle_err("open %s", file);

	if (asprintf(&buf, "%ld", (long int)proc->pid) < 0)
		handle_err("asprintf");

	len = strlen(buf);
	n = 0;

	for (;;) {
		n = write(fd, buf, len);
		if (n == -1)
			break;
		else if (n == len)
			break;
		else
			len -= n;
	}

	if (n == -1)
		DBG("Failed to write to %s", file);

	close(fd);

	free(buf);
	free(file);

	if (n != -1)
		list_add_tail(&proc->list, &cgroup->procs);

	return n >= 0? len : -1;
}

static pid_t get_proc_from_tasks(const char *path)
{
	char *file, buf[32];
	size_t len;
	ssize_t n;
	int fd;
	pid_t pid;

	if (asprintf(&file, "%s/tasks", path) < 0)
		handle_err("asprintf");

	DBG("%s", file);

	fd = open(file, O_RDONLY, S_IWUSR);
	if (fd < 0) {
		/* If the path is too long we can't do much. But we
		 * still continue. This is a soft error */
		if (errno == ENAMETOOLONG)
			return 0;

		handle_err("open");
	}

	len = sizeof(buf);
	n = read(fd, buf, len);
	if (n == -1)
		handle_err("read");

	if (n == 0)
		return 0;

	pid = strtoul(buf, NULL, 10);
	if ((errno == ERANGE && (pid == LONG_MAX || pid == LONG_MIN))
			|| (errno != 0 && pid == 0)) {
		handle_err("parse pid");
	}

	DBG("pid %ld", (long int)pid);

	return pid;
}

static void terminate_proc(pid_t pid)
{
	int status;

	if (kill(pid, SIGTERM) < 0)
		handle_err("kill");

	pid = waitpid(pid, &status, WUNTRACED | WCONTINUED);
	if (pid < 0)
		handle_err("waitpid");

	nr_children--;
	stats.reaped++;

	DBG("waitpid pid %ld status 0x%04x", (long int)pid, status);
}

static int wipe_leftovers_fn(const char *fpath, const struct stat *sb,
				int typeflag, struct FTW *ftwbuf)
{
	pid_t pid;

	if (typeflag != FTW_DP)
		return 0;

	while ((pid = get_proc_from_tasks(fpath)))
		terminate_proc(pid);

	DBG("rmdir %s", fpath);
	if (rmdir(fpath) < 0)
		handle_err("rmdir %s", fpath);

	return 0;
}

static void wipe_leftovers(const char *path)
{
	struct dirent *dir;
	char *subpath;
	DIR *d;

	DBG("");

	/* In case there are still some directories over from a
	 * previous run, remove it now */

	d = opendir(path);
	if (!d)
		handle_err("opendir");

	while ((dir = readdir(d)) != NULL) {
		if (dir->d_type != DT_DIR)
			continue;

		if (strncmp(dir->d_name, "cgt-", 4) != 0)
			continue;

		if (asprintf(&subpath, "%s/%s", path, dir->d_name) < 0)
			handle_err("asprintf");

		DBG("Remove %s", subpath);
		if (nftw(subpath, wipe_leftovers_fn, 1, FTW_DEPTH) < 0)
			handle_err("nftw");

		free(subpath);
	}

	closedir(d);
}

static void create_cgroup_siblings(struct cgroup_node *cgroup,
					unsigned int count)
{
	struct cgroup_node *node;
	unsigned int i;
	char *dir;

	for (i = 0; i < count; i++) {
		if (asprintf(&dir, "%d", cgroup_id++) < 0)
			handle_err("asprintf");

		node = create_cgroup(cgroup->path, dir);
		if (node)
			list_add_tail(&node->list, &cgroup->siblings);

		free(dir);
	}
}

static void __create_cgroup_tree(struct cgroup_node *cgroup)
{
	struct cgroup_node *cgp;
	int s;

	DBG("%s", cgroup->path);

	if (mkdir(cgroup->path,
			S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0) {
		if (errno && errno != EEXIST)
			handle_err_en(errno, "mkdir %s", cgroup->path);
	} else {
		stats.mkdir++;
	}

	if (nr_cgroups >= max_cgroups)
		return;

	s = max_cgroups - nr_cgroups > max_siblings?
		max_siblings : max_cgroups - nr_cgroups;
	nr_cgroups += s;

	create_cgroup_siblings(cgroup, s);
	list_for_each_entry(cgp, &cgroup->siblings, list)
		__create_cgroup_tree(cgp);
}

static struct cgroup_node *create_cgroup_root(const char *root_path)
{
	struct cgroup_node *root;
	char *path;

	if (asprintf(&path, "cgt-%ld", (long int)getpid()) < 0)
		handle_err("asprintf");

	root = create_cgroup(root_path, path);
	if (!root)
		handle_err_en(ENAMETOOLONG, "create root node");

	free(path);

	return root;
}

static void create_procs(struct cgroup_node *cgroup, char *argv[])
{
	struct proc_node *proc;
	struct cgroup_node *cgp;
	pid_t pid;

	if (nr_children >= max_children)
		return;

	DBG("nr_children %d", nr_children);

	pid = fork();
	switch (pid) {
	case -1:
		handle_err("fork");
		break;
	case 0:
		if (execvp(argv[0], argv) < 0)
			handle_err("execvp");

		/* we are screwed if we reach here */
		exit(EXIT_FAILURE);
		break;
	default:
		nr_children++;
		proc = malloc(sizeof(*proc));
		if (!proc)
			handle_err("malloc");
		proc->pid = pid;
	}

	DBG("%s < %ld", cgroup->path, (long int)proc->pid);
	if (add_proc_to_cgroup(cgroup, proc) < 0)
		handle_err("moving process into cgroup failed: %s < %;ld",
			cgroup->path, (long int)proc->pid);

	list_for_each_entry(cgp, &cgroup->siblings, list)
		create_procs(cgp, argv);

	stats.forked++;
}

static struct proc_node *lookup_proc(struct cgroup_node *cgroup,
						pid_t pid)
{
	struct proc_node *proc;

	list_for_each_entry(proc, &cgroup->procs, list) {
		if (pid == proc->pid)
			return proc;
	}

	return NULL;
}

static struct cgroup_node *lookup_cgroup(struct cgroup_node *cgroup,
						pid_t pid)
{
	struct cgroup_node *node = cgroup;

	int fn(struct cgroup_node *cgp, struct proc_node *proc)
	{
		if (proc->pid != pid)
			return 1;
		node = cgp;
		return 0;
	}

	proc_iterate(cgroup, fn);

	return node;
}

static struct cgroup_node *get_proc_nr(struct cgroup_node *cgroup,
					unsigned int nr)
{
	struct cgroup_node *node = cgroup;

	int fn(struct cgroup_node *cgp, struct proc_node *proc)
	{
		if (nr-- > 0)
			return 1;
		node = cgp;
		return 0;
	}

	proc_iterate(cgroup, fn);
	return node;
}

static struct cgroup_node *get_cgroup_nr(struct cgroup_node *cgroup,
						unsigned int nr)
{
	struct cgroup_node *node = NULL;

	int fn(struct cgroup_node *cgp)
	{
		if (nr-- > 0)
			return 1;
		node = cgp;
		return 0;
	}

	cgroup_iterate(cgroup, fn);

	return node;
}

static int collect_zombies(struct cgroup_node *cgroup)
{
	struct proc_node *proc;
	struct cgroup_node *cgp;
	pid_t pid;
	int status;

	pid = waitpid(-1, &status, WUNTRACED | WCONTINUED | WNOHANG);
	if (pid == 0 || pid < 0)
		return 0;

	nr_children--;

	DBG("waitpid pid %ld status 0x%04x", (long int)pid, status);

	cgp = lookup_cgroup(cgroup, pid);
	proc = lookup_proc(cgp, pid);
	list_del(&proc->list);
	free(proc);

	stats.reaped++;

	return 1;
}

static void cleanup_cgroups(struct cgroup_node *cgroup)
{
	struct proc_node *proc, *np;
	struct cgroup_node *cgp, *nc;

	list_for_each_entry_safe_reverse(proc, np, &cgroup->procs, list) {
		list_del(&proc->list);
		free(proc);
	}

	list_for_each_entry_safe_reverse(cgp, nc, &cgroup->siblings, list) {
		list_del(&cgp->list);
		cleanup_cgroups(cgp);
	}

	DBG("%s", cgroup->path);

	if (rmdir(cgroup->path) < 0)
		handle_err("rmdir %s", cgroup->path);

	stats.rmdir++;

	destroy_cgroup(cgroup);
}

static int kill_all_fn(struct cgroup_node *cgp, struct proc_node *proc)
{
	DBG("nr_children %d pid %ld", nr_children, (long int)proc->pid);
	terminate_proc(proc->pid);
	return 1;
}

static void move_proc(struct cgroup_node *src, struct cgroup_node *dst)
{
	struct proc_node *proc;

	/* First move a process around */
	DBG("\n\t%s -> \n\t%s", src->path, dst->path);

	proc = list_entry(src->procs.next, struct proc_node, list);
	list_del(&proc->list);
	if (add_proc_to_cgroup(dst, proc) < 0) {
		DBG("moving process into cgroup failed: %s < %ld",
			dst->path, (long int)proc->pid);
	}

	stats.moved++;
}

static int remove_empty_cgroups(struct cgroup_node *cgroup)
{
	struct cgroup_node *cgp, *nc;

	if (!list_empty(&cgroup->procs))
		return 0;

	list_for_each_entry_safe_reverse(cgp, nc, &cgroup->siblings, list)
		if (!remove_empty_cgroups(cgp))
			return 0;

	DBG("%s", cgroup->path);

	if (rmdir(cgroup->path) < 0) {
		/* I suspect we got the SIGCHLD faster before the
		 * kernel has finished cleanup the cgroup stuff and
		 * therefore tells us it is still busy. Need to varify
		 * this therory, */
		DBG("Failed to remove directory %s: %s",
			cgroup->path, strerror(errno));
		return 0;
	}

	stats.rmdir++;

	list_del(&cgroup->list);
	destroy_cgroup(cgroup);

	nr_cgroups--;

	return 1;
}

static void create_random_cgroups(struct cgroup_node *cgroup)
{
	struct cgroup_node *cgp;
	int gid;


	if (nr_cgroups < max_cgroups) {
		gid = rand() % (nr_cgroups + 1);
		cgp = get_cgroup_nr(cgroup, gid);
		if (!cgp)
			cgp = cgroup;
		__create_cgroup_tree(cgp);
	}

	while (nr_children < max_children) {
		gid = rand() % (nr_cgroups + 1);
		cgp = get_cgroup_nr(cgroup, gid);
		if (!cgp)
			cgp = cgroup;

		create_procs(cgp, child_argv);
	}
}

static void print_stats(void)
{
	if (!debug_enabled)
		fputs(UP_ONE, stdout);
	printf("mkdir %u rmdir %u moved %u forked %u reaped %u\n",
		stats.mkdir,
		stats.rmdir,
		stats.moved,
		stats.forked,
		stats.reaped);
}

static void run(void)
{
	struct cgroup_node *root;
	struct cgroup_node *src, *dst;
	int cid, gid;

	srand(1337);

	root = create_cgroup_root(cgroup_path);

	while (!terminate) {
		/* And now let's try to generate some new cgroups and
		 * children. */
		create_random_cgroups(root);

		/* Pick a child randomly and a destionation cgroup */
		cid = rand() % nr_children;
		gid = rand() % nr_cgroups;
		src = get_proc_nr(root, cid);
		dst = get_cgroup_nr(root, gid);

		/* We avoid the root node because we want it to stick
		 * around, that is not to be removed by
		 * remove_empty_cgroups. */
		if (src == root || dst == root || src == dst)
			goto wait;

		/* Move the child to another cgroup. */
		move_proc(src, dst);

		/* Try to remove some empty directories. */
		remove_empty_cgroups(src);
		remove_empty_cgroups(dst);

		/* Collect children which are zombies now. */
		while (collect_zombies(root))
			;
	wait:
		print_stats();
		usleep(1000);
	};

	/* Get rid of what is left over */
	proc_iterate(root, kill_all_fn);
	cleanup_cgroups(root);
	print_stats();
}

static unsigned int get_arg_unsigned(const char *arg, const char *name)
{
	unsigned int n;

	errno = 0;
	n = strtoul(arg, NULL, 10);
	if (errno == ERANGE && n == ULONG_MAX) {
		fprintf(stderr, "Invalid argument <%s>\n", name);
		exit(EXIT_FAILURE);
	}

	return n;
}

static int get_arg_signed(const char *arg, const char *name)
{
	int n;

	errno = 0;
	n = strtol(arg, NULL, 10);
	if (errno == ERANGE && (n == LONG_MAX || n == LONG_MIN)) {
		fprintf(stderr, "Invalid argument <%s>\n", name);
		exit(EXIT_FAILURE);
	}

	return n;
}

static void usage(const char *progname)
{
	printf("Usage: %s [cstdh] hog\n", progname);
	printf("\t-g --cgroups\t- Maximal number of cgroups to create\n");
	printf("\t-c --children\t- Maximal number of children\n");
	printf("\t-s --siblings\t- Maximal number of sub-cgroups per cgroup\n");
	printf("\t-t --time\t- Time running the hog\n");
	printf("\t-p --path\t- Path to cgroup controller [/sys/fs/cgroup/memory]\n");
	printf("\t-d --debug\t- Enable debuggin output\n");
	printf("\t-h --help\t- Print usage (d'oh)\n");
}

static struct option long_options[] = {
	{ "cgroups",	required_argument,	0,	'g' },
	{ "children",	required_argument,	0,	'c' },
	{ "siblings",	required_argument,	0,	's' },
	{ "time",	required_argument,	0,	't' },
	{ "path",	required_argument,	0,	'p' },
	{ "debug",	no_argument,		0,	'd' },
	{ "help",	no_argument,		0,	'h' },
	{ 0,		0,			0,	0 },
};

int main(int argc, char *argv[])
{
	int option_index, c;
	char *path = NULL;
	int time = 60;
	struct itimerval itv;
	struct sigaction sa;

	for (;;) {
		c = getopt_long(argc, argv, "c:g:s:t:p:dh",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			max_children = get_arg_unsigned(optarg, "children");
			break;
		case 'g':
			max_cgroups = get_arg_unsigned(optarg, "cgroups");
			break;
		case 's':
			max_siblings = get_arg_unsigned(optarg, "siblings");
			break;
		case 't':
			time = get_arg_signed(optarg, "time");
			break;
		case 'p':
			path = strdup(optarg);
			break;
		case 'd':
			debug_enabled = 1;
			break;
		case 'h':
			usage(basename(argv[0]));
			exit(EXIT_SUCCESS);
			break;
		default:
			fprintf(stderr, "unknown agrument\n");
			exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Expected arguments after options\n");
		exit(EXIT_FAILURE);
	}

	cgroup_path = path ? path : strdup(CGROUP_DEFAULT_PATH);
	if (!cgroup_path)
		handle_err("Out of memory");

	wipe_leftovers(cgroup_path);

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = signal_handler;
	if (sigaction(SIGALRM, &sa, NULL) < 0)
		handle_err("Couldn't install signal handler");
	if (sigaction(SIGINT, &sa, NULL) < 0)
		handle_err("Couldn't install signal handler");
	if (sigaction(SIGTERM, &sa, NULL) < 0)
		handle_err("Couldn't install signal handler");

	if (time != 0) {
		itv.it_interval.tv_sec = 0;
		itv.it_interval.tv_usec = 0;
		itv.it_value.tv_sec = time;
		itv.it_value.tv_usec = 0;

		if (setitimer(ITIMER_REAL, &itv, 0) < 0)
			handle_err("Couldn't program timer");
	}

	child_argv = &argv[optind];

	printf("\n");
	run();

	free(cgroup_path);

	return EXIT_SUCCESS;
}
