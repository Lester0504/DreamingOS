/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * BGAPI NCP transport for the Silicon Labs EFR32MG21 on the Gemtek W1700K.
 *
 * The co-processor hangs off UART2 (/dev/ttyS1) and runs a Silabs BGAPI NCP
 * image, not an H4 HCI one, so the kernel Bluetooth stack and btattach cannot
 * talk to it. BGAPI is a request/response application protocol; this file
 * implements the wire framing and the synchronous command path, and queues
 * events for the caller.
 *
 * Command and event identifiers, payload layouts and enum values are taken
 * from the Gecko SDK v4.2.1 headers (protocol/bluetooth/inc/sl_bt_api.h and
 * sl_bgapi.h), which is the SDK the device reports via system_get_version
 * (4.2.1 build 342).
 *
 * Wire header is four bytes:
 *
 *   [0] message type | device type | high 3 bits of payload length
 *   [1] low 8 bits of payload length
 *   [2] class id
 *   [3] message id
 *
 * The SDK spells the same four bytes as a little-endian u32 constant, so
 * sl_bt_cmd_system_hello_id == 0x00010020 is the byte sequence 20 00 01 00.
 */
#ifndef DREAMINGWRT_APD_APD_BGAPI_H
#define DREAMINGWRT_APD_APD_BGAPI_H

#include <stddef.h>
#include <stdint.h>

#define APD_BGAPI_HEADER_LEN	4
#define APD_BGAPI_MAX_PAYLOAD	256

#define APD_BGAPI_TYPE_MASK		0x80
#define APD_BGAPI_TYPE_EVENT	0x80
#define APD_BGAPI_DEV_BT		0x20

/* system */
#define APD_BG_CMD_SYSTEM_HELLO			0x00010020u
#define APD_BG_CMD_SYSTEM_RESET			0x01010020u
#define APD_BG_CMD_SYSTEM_GET_VERSION		0x1b010020u
#define APD_BG_CMD_SYSTEM_GET_IDENTITY_ADDRESS	0x15010020u
#define APD_BG_EVT_SYSTEM_BOOT			0x000100a0u

/* advertiser */
#define APD_BG_CMD_ADVERTISER_CREATE_SET		0x01040020u
#define APD_BG_CMD_ADVERTISER_DELETE_SET		0x02040020u
#define APD_BG_CMD_ADVERTISER_SET_TIMING		0x03040020u
#define APD_BG_CMD_ADVERTISER_STOP			0x0a040020u
#define APD_BG_CMD_LEGACY_ADVERTISER_SET_DATA	0x00560020u
#define APD_BG_CMD_LEGACY_ADVERTISER_START		0x02560020u

/* gatt database builder */
#define APD_BG_CMD_GATTDB_NEW_SESSION		0x00460020u
#define APD_BG_CMD_GATTDB_ADD_SERVICE		0x01460020u
#define APD_BG_CMD_GATTDB_ADD_UUID128_CHAR		0x06460020u
#define APD_BG_CMD_GATTDB_START_SERVICE		0x0b460020u
#define APD_BG_CMD_GATTDB_COMMIT			0x0f460020u

/* gatt server */
#define APD_BG_CMD_GATTS_SET_MAX_MTU		0x0a0a0020u
#define APD_BG_CMD_GATTS_SEND_USER_READ_RSP		0x030a0020u
#define APD_BG_CMD_GATTS_SEND_USER_WRITE_RSP	0x040a0020u
#define APD_BG_CMD_GATTS_SEND_NOTIFICATION		0x0f0a0020u
#define APD_BG_EVT_GATTS_ATTRIBUTE_VALUE		0x000a00a0u
#define APD_BG_EVT_GATTS_USER_READ_REQUEST		0x010a00a0u
#define APD_BG_EVT_GATTS_USER_WRITE_REQUEST		0x020a00a0u
#define APD_BG_EVT_GATTS_CHARACTERISTIC_STATUS	0x030a00a0u

/* connection / gatt client side events we care about */
#define APD_BG_EVT_CONNECTION_OPENED		0x000600a0u
#define APD_BG_EVT_CONNECTION_CLOSED		0x010600a0u
#define APD_BG_EVT_CONNECTION_PARAMETERS		0x020600a0u
#define APD_BG_EVT_CONNECTION_PHY_STATUS		0x040600a0u
#define APD_BG_EVT_CONNECTION_REMOTE_USED_FEATURES	0x080600a0u
#define APD_BG_EVT_GATT_MTU_EXCHANGED		0x000900a0u

/* gattdb enums */
#define APD_BG_GATTDB_PRIMARY_SERVICE	0x00
#define APD_BG_GATTDB_ADVERTISED_SERVICE	0x01
#define APD_BG_GATTDB_FIXED_LENGTH_VALUE	0x01
#define APD_BG_GATTDB_VARIABLE_LENGTH_VALUE	0x02
#define APD_BG_GATTDB_USER_MANAGED_VALUE	0x03

#define APD_BG_CHAR_READ			0x0002
#define APD_BG_CHAR_WRITE_NO_RESPONSE	0x0004
#define APD_BG_CHAR_WRITE			0x0008
#define APD_BG_CHAR_NOTIFY			0x0010

/* advertiser enums */
#define APD_BG_ADV_NON_CONNECTABLE		0x00
#define APD_BG_ADV_CONNECTABLE_SCANNABLE	0x02
#define APD_BG_ADV_DATA_PACKET		0x00
#define APD_BG_ADV_SCAN_RESPONSE_PACKET	0x01

/* the handful of sl_status_t values this code reacts to */
#define APD_BG_STATUS_OK			0x0000
#define APD_BG_STATUS_NOT_IMPLEMENTED	0x000f
#define APD_BG_STATUS_INVALID_PARAMETER	0x0021

struct apd_bgapi_msg {
	uint32_t id;			/* header as a little-endian u32, length bits masked out */
	uint8_t cls;
	uint8_t msg;
	uint8_t is_event;
	uint16_t len;
	uint8_t payload[APD_BGAPI_MAX_PAYLOAD];
};

struct apd_bgapi_dev {
	int fd;
	char path[64];
	unsigned int baud;

	/* Events that arrived while waiting for a command response. BGAPI
	 * interleaves them freely, so they must be kept rather than dropped. */
	struct apd_bgapi_msg pending[16];
	unsigned int pending_head;
	unsigned int pending_count;

	char err[160];
};

/* Open the NCP tty and put it in raw 8N1 at the given baud rate. */
int apd_bgapi_open(struct apd_bgapi_dev *dev, const char *path, unsigned int baud);
void apd_bgapi_close(struct apd_bgapi_dev *dev);

/*
 * Pin the Airoha BRD divider back to 1 through /dev/mem.
 *
 * Only needed on kernels without 887-uart-airoha-do-not-clobber-BRD-with-
 * generic-divisor.patch. There, serial8250_do_set_termios() calls
 * en7523_set_uart_baud_rate() (which sets BRD=1 and programs XYD) and then
 * serial8250_set_divisor() writes the generic quot into DLL/DLM - the same
 * registers as BRDL/BRDH in the Airoha register space - so the line rate ends
 * up divided by quot. Requesting 460800 happens to work because
 * clock-frequency/16 == 460800 makes quot == 1.
 *
 * Call this after apd_bgapi_open(). On a kernel carrying 887 it is unnecessary and
 * should not be used.
 */
int apd_bgapi_pin_brd(struct apd_bgapi_dev *dev, unsigned long uart_phys);

/* UART2 on the AN7581, where the W1700K wires the EFR32MG21. */
#define APD_AN7581_UART2_PHYS	0x1fbf0300UL

/*
 * Send a command and wait for its response. Events seen while waiting are
 * queued. Returns 0 when a response arrived (check the sl_status_t in the
 * payload separately), -1 on transport failure or timeout.
 */
int apd_bgapi_command(struct apd_bgapi_dev *dev, uint32_t id, const uint8_t *payload,
		  uint16_t len, struct apd_bgapi_msg *rsp, int timeout_ms);

/* Send a command that has no response (system_reset). */
int apd_bgapi_command_noreply(struct apd_bgapi_dev *dev, uint32_t id,
			  const uint8_t *payload, uint16_t len);

/*
 * Return the next event, from the queue first and then from the wire.
 * Returns 1 on an event, 0 on timeout, -1 on transport failure.
 */
int apd_bgapi_next_event(struct apd_bgapi_dev *dev, struct apd_bgapi_msg *evt, int timeout_ms);

/* First two payload bytes of a command response are the sl_status_t. */
uint16_t apd_bgapi_result(const struct apd_bgapi_msg *rsp);

const char *apd_bgapi_error(const struct apd_bgapi_dev *dev);
const char *apd_bgapi_status_name(uint16_t status);

/* Little-endian payload accessors; they clamp rather than read out of bounds. */
uint16_t apd_bgapi_get_u16(const struct apd_bgapi_msg *m, uint16_t off);
uint32_t apd_bgapi_get_u32(const struct apd_bgapi_msg *m, uint16_t off);

#endif /* DREAMINGWRT_APD_APD_BGAPI_H */
