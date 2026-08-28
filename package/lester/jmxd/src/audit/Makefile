# ── dreamingwrt-auditd: log audit worker ─────────────────────────────
#
# Lightweight daemon reading jmx_audit_* tables and exposing via ubus.
#
# Required libraries (via LDFLAGS from parent Makefile):
#   libubus             ubus IPC
#   libubox             blobmsg, utils
#   libsqlite3          SQLite3 database
#
# corpus/dwsig.c pulls in OpenSSL EVP, and the package build does not pass
# -lcrypto in LDFLAGS for this subdirectory, so link it here rather than
# depending on the caller to supply it.
# ──────────────────────────────────────────────────────────────────────

CC ?= gcc
CFLAGS ?= -Wall -Wextra -Wno-unused-parameter
LDFLAGS ?=
AUDITD_LIBS := -lcrypto

TARGET := dreamingwrt-auditd

all: $(TARGET)

$(TARGET): jmx_auditd.c ../corpus/dwsig.c ../corpus/dwsig.h ../jmx_storage_guard.c ../jmx_storage_guard.h \
	../jmx_system_data_path.c ../jmx_system_data_path.h \
	../jmx_path_provider.c ../jmx_path_provider.h
	$(CC) $(CFLAGS) -I.. -o $@ jmx_auditd.c ../corpus/dwsig.c ../jmx_storage_guard.c \
		../jmx_system_data_path.c ../jmx_path_provider.c $(LDFLAGS) $(AUDITD_LIBS)

clean:
	-rm -f $(TARGET)

.PHONY: all clean
