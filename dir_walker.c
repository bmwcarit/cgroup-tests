/*
 *
 *  cgroup tests - dir_walker
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

/* Iterate over cgroups and try to read all files. */

#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <ftw.h>
#include <libgen.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>

#define BUF_SIZE 4096

#define DBG(fmt, arg...) do { \
	if (debug_enabled) \
		printf("%s() " fmt "\n", __FUNCTION__ , ## arg); \
} while (0)

#define handle_err(fmt, arg...)						\
        do {								\
		log_error("ERROR: %s: " fmt "\n", strerror(errno), ## arg); \
		exit(EXIT_FAILURE);					\
	} while (0)

static int debug_enabled;
static int verbose_level;

static void log_error(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

static int read_fn(const char *fpath, const struct stat *sb, int typeflag,
			struct FTW *ftwbuf)
{
	int fd;
	char buf[BUF_SIZE];
	char *p;
	ssize_t n;
	size_t l, t;

	if (typeflag != FTW_F)
		return 0;

	if (!(sb->st_mode & (S_IRUSR | S_IRGRP | S_IROTH)))
		return 0;

	fd = open(fpath, 0);
	if (fd < 0) {
		DBG("failed to open %s", fpath);
		return 0;
	}

	l = sizeof(buf);
	p = buf;
	t = 0;
	for (;;) {
		n = read(fd, p, l);
		if (n > 0) {
			l -= n;
			if (l < 0)
				break;
			p += n;
			t += n;
		} else if (n == 0) {
			break;
		} else {
			DBG("failed reading %s", fpath);
			break;
		}
	}
	buf[t - 1] = '\0';

	if (verbose_level) {
		printf("%s\n", fpath);
		printf("%s\n\n", buf);
	}

	close(fd);

	return 0;
}

static void usage(const char *progname)
{
	printf("Usage: %s [lvdh] PATH\n", progname);
	printf("\t-l --loop NUMBER\t- Loop NUMBER times (-1 == forever)\n");
	printf("\t-v --verbose\t\t- Print file content\n");
	printf("\t-d --debug\t\t- Enable debuggin output\n");
	printf("\t-h --help\t\t- Print usage (d'oh)\n");
}

static struct option long_options[] = {
	{ "loop",	no_argument,		0,	'l' },
	{ "verbose",	no_argument,		0,	'v' },
	{ "debug",	no_argument,		0,	'd' },
	{ "help",	no_argument,		0,	'h' },
	{ 0,		0,			0,	0 },
};

int main(int argc, char *argv[])
{
	int option_index, c;
	int loop = 1;

	for (;;) {
		c = getopt_long(argc, argv, "l:dhv",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'l':
			loop = strtoul(optarg, NULL, 10);
			if ((errno == ERANGE &&	(loop == LONG_MAX ||
							loop == LONG_MIN))
					|| (errno != 0 && loop == 0)) {
				fprintf(stderr,
					"Invalid argument for <loop>\n");
			}
			break;
		case 'v':
			verbose_level = 1;
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
		fprintf(stderr, "Expected argument PATH after options\n");
		exit(EXIT_FAILURE);
	}

	while (loop) {
		if (nftw(argv[optind], read_fn, 20, FTW_DEPTH) < 0)
			handle_err("%s", argv[optind]);

		if (loop < 0)
			continue;

		loop--;
	}

	return 0;
}
