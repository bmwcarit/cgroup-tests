/*
 *
 *  cgroup tests - memory_hog
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

/* Allocate some memory and write a pattern into it. After release it. */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>

#define DBG(fmt, arg...) do { \
	if (debug_enabled) \
		printf("%s:%s() " fmt "\n", __FILE__, __FUNCTION__ , ## arg); \
} while (0)

#define handle_err_en(en, msg)                                          \
        do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

#define handle_err(msg)                                                 \
        do { perror(msg); exit(EXIT_FAILURE); } while (0)

static int debug_enabled;

static int hog(unsigned long size, unsigned long idle, unsigned long loop)
{
	char *buf, *p;
	int i = 0;

	if (loop == 0)
		loop = 1;

	while (loop) {
		DBG("%lu loops to go", loop);
		DBG("allocating memory %lu bytes", size);
		p = buf = malloc(size);
		if (!buf)
			handle_err("malloc");

		DBG("write data");
		while (p < buf + size)
			*p++ = i++;

		if (idle) {
			DBG("idle for %lu", idle);
			sleep(idle);
		}

		DBG("free memory");
		free(buf);

		loop--;
	}

	return 0;
}

static void usage(const char *progname)
{
	printf("%s: \n", progname);
	printf("\t-b --buffer\t- Buffer allocation size\n");
	printf("\t-s --sleep\t- Wait for seconds after allocation\n");
	printf("\t-l --loop\t- Repeat test in a loop\n");
	printf("\t-d --debug\t- Enable debuggin output\n");
	printf("\t-h --help\t- Print usage (d'oh)\n");
}

static struct option long_options[] = {
	{ "buffer",	required_argument,	0,	'b' },
	{ "sleep",	required_argument,	0,	's' },
	{ "loop",	required_argument,	0,	'l' },
	{ "debug",	no_argument,		0,	'd' },
	{ "help",	no_argument,		0,	'h' },
	{ 0,		0,			0,	0 },
};

int main(int argc, char *argv[])
{
	char *endptr;
	int option_index;
	int c;
	unsigned long buf_size = 10 * 1024 * 1024;
	unsigned long idle = 1;
	unsigned long loop = 5;

	for (;;) {
		c = getopt_long(argc, argv, "b:s:l:dh",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'b':
			errno = 0;
			buf_size = strtoul(optarg, &endptr, 10);
			if ((errno == ERANGE &&	(buf_size == ULONG_MAX))
					|| (errno != 0 && buf_size == 0)) {
				handle_err("Invalid argument <buffer>");
			}
			if (!strcasecmp("G", endptr))
				buf_size *= 1024 * 1024 * 1024;
			else if (!strcasecmp("M", endptr))
				buf_size *= 1024 * 1024;
			else if (!strcasecmp("K", endptr))
				buf_size *= 1024;

			break;
		case 's':
			errno = 0;
			idle = strtoul(optarg, NULL, 10);
			if ((errno == ERANGE) && (idle == ULONG_MAX)) {
				handle_err("Invalid argument <sleep>");
			}
			break;
		case 'l':
			errno = 0;
			loop = strtoul(optarg, NULL, 10);
			if ((errno == ERANGE) && (loop == ULONG_MAX)) {
				handle_err("Invalid argument <loop>");
			}
			break;
		case 'd':
			debug_enabled = 1;
			break;
		case 'h':
			usage(basename(argv[0]));
			exit(EXIT_SUCCESS);
			break;
		default:
			printf("unknown agrument\n");
			exit(EXIT_FAILURE);
		}
	}

	return hog(buf_size, idle, loop);
}
