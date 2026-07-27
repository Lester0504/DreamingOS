# jmx rule loader - userspace protobuf decoder + netlink push
# Not an OpenWrt package Makefile - this is a source-level Makefile
# for development/testing. The real build integration goes in jmxd/Makefile.

CC ?= gcc
CFLAGS ?= -Wall -O2 -I.. -I.
LDFLAGS ?= -lcrypto -lz

LOADER_SRCS = jmx_rule.c jmx_proto_decode.c jmx_nl_push.c
LOADER_OBJS = $(LOADER_SRCS:.c=.o)

.PHONY: all clean

all: $(LOADER_OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(LOADER_OBJS)
