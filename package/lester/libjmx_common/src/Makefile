# ── libjmx_common.so ──
# UCI helper wrappers: jmx_uci_{get,set,add,del,commit}_*
# 17 exported functions, ~250 LOC

OBJS := jmx_uci.o
LIB_NAME := libjmx_common.so

# -fPIC is required for shared libraries.
# It's injected via TARGET_CFLAGS in the package Makefile.
# CFLAGS here should NOT override it.

all: $(LIB_NAME)

$(LIB_NAME): $(OBJS)
	$(CC) -shared -Wl,--gc-sections -o $@ $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	-rm -f $(LIB_NAME) $(OBJS)

.PHONY: all clean
