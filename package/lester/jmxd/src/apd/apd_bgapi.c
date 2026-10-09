/* SPDX-License-Identifier: GPL-2.0-or-later */
/* BGAPI NCP transport. See bgapi.h for the wire format and provenance. */
#include "apd_bgapi.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define PENDING_SLOTS	(sizeof(((struct apd_bgapi_dev *)0)->pending) / \
			 sizeof(((struct apd_bgapi_dev *)0)->pending[0]))

static void set_err(struct apd_bgapi_dev *dev, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static void set_err(struct apd_bgapi_dev *dev, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(dev->err, sizeof(dev->err), fmt, ap);
	va_end(ap);
}

static long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static speed_t baud_const(unsigned int baud)
{
	switch (baud) {
	case 9600:	return B9600;
	case 19200:	return B19200;
	case 38400:	return B38400;
	case 57600:	return B57600;
	case 115200:	return B115200;
	case 230400:	return B230400;
	case 460800:	return B460800;
	case 921600:	return B921600;
	default:	return 0;
	}
}

int apd_bgapi_open(struct apd_bgapi_dev *dev, const char *path, unsigned int baud)
{
	struct termios tio;
	speed_t speed;

	memset(dev, 0, sizeof(*dev));
	dev->fd = -1;

	speed = baud_const(baud);
	if (!speed) {
		set_err(dev, "unsupported baud rate %u", baud);
		return -1;
	}

	snprintf(dev->path, sizeof(dev->path), "%s", path);
	dev->baud = baud;

	dev->fd = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (dev->fd < 0) {
		set_err(dev, "open %s: %s", path, strerror(errno));
		return -1;
	}

	if (tcgetattr(dev->fd, &tio) < 0) {
		set_err(dev, "tcgetattr %s: %s", path, strerror(errno));
		close(dev->fd);
		dev->fd = -1;
		return -1;
	}

	cfmakeraw(&tio);
	tio.c_cflag |= CLOCAL | CREAD;
	tio.c_cflag &= ~(unsigned)CRTSCTS;
	tio.c_cflag &= ~(unsigned)CSTOPB;
	tio.c_cflag &= ~(unsigned)PARENB;
	tio.c_cc[VMIN] = 0;
	tio.c_cc[VTIME] = 0;
	cfsetispeed(&tio, speed);
	cfsetospeed(&tio, speed);

	if (tcsetattr(dev->fd, TCSANOW, &tio) < 0) {
		set_err(dev, "tcsetattr %s: %s", path, strerror(errno));
		close(dev->fd);
		dev->fd = -1;
		return -1;
	}

	tcflush(dev->fd, TCIOFLUSH);
	return 0;
}

void apd_bgapi_close(struct apd_bgapi_dev *dev)
{
	if (dev->fd >= 0) {
		close(dev->fd);
		dev->fd = -1;
	}
}

/*
 * Airoha 8250 register offsets in the normalised (reg-shift 2) space.
 * BRDL/BRDH alias the generic DLL/DLM, which is the whole problem 887 fixes.
 */
#define AIROHA_REG_BRDL	0x00
#define AIROHA_REG_BRDH	0x04
#define AIROHA_REG_LCR	0x0c
#define LCR_DLAB	0x80

int apd_bgapi_pin_brd(struct apd_bgapi_dev *dev, unsigned long uart_phys)
{
	long page_size = sysconf(_SC_PAGESIZE);
	unsigned long page;
	volatile uint32_t *regs;
	uint32_t lcr, brdl, brdh;
	void *map;
	int fd;

	if (page_size <= 0) {
		set_err(dev, "sysconf(_SC_PAGESIZE) failed");
		return -1;
	}
	page = uart_phys & ~(unsigned long)(page_size - 1);

	fd = open("/dev/mem", O_RDWR | O_SYNC | O_CLOEXEC);
	if (fd < 0) {
		set_err(dev, "open /dev/mem: %s", strerror(errno));
		return -1;
	}

	map = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		   fd, (off_t)page);
	close(fd);
	if (map == MAP_FAILED) {
		set_err(dev, "mmap 0x%lx: %s", page, strerror(errno));
		return -1;
	}

	regs = (volatile uint32_t *)((char *)map + (uart_phys - page));

	lcr = regs[AIROHA_REG_LCR / 4];
	regs[AIROHA_REG_LCR / 4] = lcr | LCR_DLAB;
	brdl = regs[AIROHA_REG_BRDL / 4] & 0xff;
	brdh = regs[AIROHA_REG_BRDH / 4] & 0xff;
	if (brdl != 1 || brdh != 0) {
		regs[AIROHA_REG_BRDL / 4] = 1;
		regs[AIROHA_REG_BRDH / 4] = 0;
	}
	regs[AIROHA_REG_LCR / 4] = lcr & ~(uint32_t)LCR_DLAB;

	munmap(map, (size_t)page_size);

	/* Report whether anything needed fixing, so the caller can tell a
	 * kernel with 887 from one without. */
	return (brdl != 1 || brdh != 0) ? 1 : 0;
}

const char *apd_bgapi_error(const struct apd_bgapi_dev *dev)
{
	return dev->err[0] ? dev->err : "no error";
}

uint16_t apd_bgapi_result(const struct apd_bgapi_msg *rsp)
{
	if (rsp->len < 2)
		return 0xffff;
	return (uint16_t)(rsp->payload[0] | (rsp->payload[1] << 8));
}

uint16_t apd_bgapi_get_u16(const struct apd_bgapi_msg *m, uint16_t off)
{
	if (off + 2 > m->len)
		return 0;
	return (uint16_t)(m->payload[off] | (m->payload[off + 1] << 8));
}

uint32_t apd_bgapi_get_u32(const struct apd_bgapi_msg *m, uint16_t off)
{
	if (off + 4 > m->len)
		return 0;
	return (uint32_t)m->payload[off] |
	       ((uint32_t)m->payload[off + 1] << 8) |
	       ((uint32_t)m->payload[off + 2] << 16) |
	       ((uint32_t)m->payload[off + 3] << 24);
}

const char *apd_bgapi_status_name(uint16_t status)
{
	switch (status) {
	case APD_BG_STATUS_OK:			return "ok";
	case APD_BG_STATUS_NOT_IMPLEMENTED:		return "not_implemented";
	case APD_BG_STATUS_INVALID_PARAMETER:	return "invalid_parameter";
	case 0x0001:				return "fail";
	case 0x0002:				return "invalid_state";
	case 0x0003:				return "not_ready";
	case 0x000a:				return "not_supported";
	case 0x001a:				return "out_of_bounds";
	case 0x0018:				return "no_more_resource";
	case 0x1101:				return "bt_att_invalid_handle";
	default:				return "unknown";
	}
}

/* Read exactly len bytes, or fail. deadline is an absolute now_ms() value. */
static int read_exact(struct apd_bgapi_dev *dev, uint8_t *buf, size_t len,
		      long deadline)
{
	size_t got = 0;

	while (got < len) {
		struct pollfd pfd = { .fd = dev->fd, .events = POLLIN };
		long remain = deadline - now_ms();
		ssize_t n;
		int rc;

		if (remain <= 0)
			return 0;	/* timeout */

		rc = poll(&pfd, 1, (int)remain);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			set_err(dev, "poll %s: %s", dev->path, strerror(errno));
			return -1;
		}
		if (rc == 0)
			return 0;	/* timeout */

		n = read(dev->fd, buf + got, len - got);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			set_err(dev, "read %s: %s", dev->path, strerror(errno));
			return -1;
		}
		if (n == 0)
			continue;

		got += (size_t)n;
	}

	return 1;
}

/* Pull one whole BGAPI message off the wire. 1 = got one, 0 = timeout. */
static int read_msg(struct apd_bgapi_dev *dev, struct apd_bgapi_msg *m, long deadline)
{
	uint8_t hdr[APD_BGAPI_HEADER_LEN];
	uint16_t len;
	int rc;

	rc = read_exact(dev, hdr, sizeof(hdr), deadline);
	if (rc <= 0)
		return rc;

	len = (uint16_t)(((hdr[0] & 0x07) << 8) | hdr[1]);
	if (len > APD_BGAPI_MAX_PAYLOAD) {
		/* Desynchronised: a valid BT message never exceeds the buffer. */
		set_err(dev, "framing error: payload length %u on class 0x%02x msg 0x%02x",
			len, hdr[2], hdr[3]);
		tcflush(dev->fd, TCIFLUSH);
		return -1;
	}

	memset(m, 0, sizeof(*m));
	m->cls = hdr[2];
	m->msg = hdr[3];
	m->is_event = (hdr[0] & APD_BGAPI_TYPE_MASK) == APD_BGAPI_TYPE_EVENT;
	m->len = len;
	/* Same masking the SDK's SL_APD_BGAPI_MSG_ID does, so the value can be
	 * compared against the sl_bt_cmd_*_id / sl_bt_evt_*_id constants. */
	m->id = ((uint32_t)hdr[0] & 0xf8u) |
		((uint32_t)hdr[2] << 16) |
		((uint32_t)hdr[3] << 24);

	if (len) {
		rc = read_exact(dev, m->payload, len, deadline);
		if (rc <= 0) {
			if (rc == 0)
				set_err(dev, "truncated message: class 0x%02x msg 0x%02x expected %u payload bytes",
					m->cls, m->msg, len);
			return rc ? rc : -1;
		}
	}

	return 1;
}

static void queue_event(struct apd_bgapi_dev *dev, const struct apd_bgapi_msg *m)
{
	unsigned int slot;

	if (dev->pending_count == PENDING_SLOTS) {
		/* Drop the oldest; the newest state is the interesting one. */
		dev->pending_head = (dev->pending_head + 1) % PENDING_SLOTS;
		dev->pending_count--;
	}

	slot = (dev->pending_head + dev->pending_count) % PENDING_SLOTS;
	dev->pending[slot] = *m;
	dev->pending_count++;
}

static int write_frame(struct apd_bgapi_dev *dev, uint32_t id,
		       const uint8_t *payload, uint16_t len)
{
	uint8_t buf[APD_BGAPI_HEADER_LEN + APD_BGAPI_MAX_PAYLOAD];
	size_t total = APD_BGAPI_HEADER_LEN + len;
	size_t off = 0;

	if (len > APD_BGAPI_MAX_PAYLOAD) {
		set_err(dev, "payload of %u bytes exceeds the BGAPI limit", len);
		return -1;
	}

	buf[0] = (uint8_t)((id & 0xf8u) | ((len >> 8) & 0x07u));
	buf[1] = (uint8_t)(len & 0xff);
	buf[2] = (uint8_t)((id >> 16) & 0xff);
	buf[3] = (uint8_t)((id >> 24) & 0xff);
	if (len)
		memcpy(buf + APD_BGAPI_HEADER_LEN, payload, len);

	while (off < total) {
		ssize_t n = write(dev->fd, buf + off, total - off);

		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			set_err(dev, "write %s: %s", dev->path, strerror(errno));
			return -1;
		}
		off += (size_t)n;
	}

	return 0;
}

int apd_bgapi_command(struct apd_bgapi_dev *dev, uint32_t id, const uint8_t *payload,
		  uint16_t len, struct apd_bgapi_msg *rsp, int timeout_ms)
{
	long deadline;

	if (write_frame(dev, id, payload, len) < 0)
		return -1;

	deadline = now_ms() + timeout_ms;

	for (;;) {
		struct apd_bgapi_msg m;
		int rc = read_msg(dev, &m, deadline);

		if (rc < 0)
			return -1;
		if (rc == 0) {
			set_err(dev, "timeout waiting for response to class 0x%02x msg 0x%02x",
				(unsigned)((id >> 16) & 0xff),
				(unsigned)((id >> 24) & 0xff));
			return -1;
		}

		if (m.is_event) {
			queue_event(dev, &m);
			continue;
		}

		if (m.id != (id & 0xffff00f8u)) {
			/* A stale response from an earlier aborted command. */
			continue;
		}

		*rsp = m;
		return 0;
	}
}

int apd_bgapi_command_noreply(struct apd_bgapi_dev *dev, uint32_t id,
			  const uint8_t *payload, uint16_t len)
{
	return write_frame(dev, id, payload, len);
}

int apd_bgapi_next_event(struct apd_bgapi_dev *dev, struct apd_bgapi_msg *evt, int timeout_ms)
{
	long deadline;

	if (dev->pending_count) {
		*evt = dev->pending[dev->pending_head];
		dev->pending_head = (dev->pending_head + 1) % PENDING_SLOTS;
		dev->pending_count--;
		return 1;
	}

	deadline = now_ms() + timeout_ms;

	for (;;) {
		struct apd_bgapi_msg m;
		int rc = read_msg(dev, &m, deadline);

		if (rc <= 0)
			return rc;
		if (m.is_event) {
			*evt = m;
			return 1;
		}
		/* Unsolicited response; nothing is waiting for it. */
	}
}
