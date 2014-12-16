# Makefile for sched selftests.

CC = $(CROSS_COMPILE)gcc
CFLAGS += -Wall
LDFLAGS += -g -O0

all: cgroup_tests memory_hog dir_walker

check: all
	./cgroup_tests ./memory_hog

clean:
	rm -f cgroup_tests memory_hog dir_walker

.PHONY: all
