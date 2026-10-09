// SPDX-License-Identifier: GPL-2.0-or-later
#include "wire.h"
#include <string.h>

static void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

uint32_t cw_wire_read_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int cw_wire_is_control(uint8_t type)
{
    switch (type) {
    case CW_OP_HELLO: case CW_OP_WELCOME: case CW_OP_PING: case CW_OP_PONG:
    case CW_OP_SERVICES: case CW_OP_GENERATION: case CW_OP_GOAWAY:
    case CW_OP_AUTH_CHALLENGE: case CW_OP_AUTH_RESPONSE:
        return 1;
    default:
        return 0;
    }
}

int cw_wire_is_data(uint8_t type)
{
    switch (type) {
    case CW_OP_OPEN: case CW_OP_RESP: case CW_OP_DATA: case CW_OP_FIN:
    case CW_OP_RESET: case CW_OP_WINDOW:
        return 1;
    default:
        return 0;
    }
}

/* control ops require stream_id==0, data ops require !=0; WINDOW allows both
 * (stream_id 0 == connection-level flow credit). */
static int stream_id_ok(uint8_t type, uint32_t sid)
{
    if (type == CW_OP_WINDOW)
        return 1;
    if (cw_wire_is_control(type))
        return sid == 0;
    return sid != 0;
}

/* fixed-size payload rules for the control-metadata data ops. */
static int length_ok(uint8_t type, uint32_t length)
{
    if (length > CW_WIRE_FRAME_MAX)
        return 0;
    switch (type) {
    case CW_OP_FIN:
        return length == 0;
    case CW_OP_RESET:
    case CW_OP_WINDOW:
        return length == 4;
    default:
        return 1;
    }
}

long cw_wire_encode(uint8_t *out, size_t cap, uint8_t type, uint16_t flags,
                    uint32_t stream_id, const uint8_t *payload, uint32_t length)
{
    if (!out)
        return -1;
    if (!cw_wire_is_control(type) && !cw_wire_is_data(type))
        return -1;
    if (!length_ok(type, length) || !stream_id_ok(type, stream_id))
        return -1;
    if (length > 0 && !payload)
        return -1;
    if (cap < (size_t)CW_WIRE_HDR + length)
        return -1;
    out[0] = CW_WIRE_VERSION;
    out[1] = type;
    put_u16(out + 2, flags);
    put_u32(out + 4, stream_id);
    put_u32(out + 8, length);
    if (length)
        memcpy(out + CW_WIRE_HDR, payload, length);
    return (long)((size_t)CW_WIRE_HDR + length);
}

int cw_wire_decode(const uint8_t *in, size_t len, struct cw_frame *frame,
                   size_t *consumed, int *err)
{
    if (consumed)
        *consumed = 0;
    if (err)
        *err = CW_ERR_NONE;
    if (!in || !frame) {
        if (err) *err = CW_ERR_PROTOCOL;
        return CW_WIRE_ERROR;
    }
    if (len < CW_WIRE_HDR)
        return CW_WIRE_NEED_MORE;

    uint8_t version = in[0];
    uint8_t type = in[1];
    uint16_t flags = get_u16(in + 2);
    uint32_t sid = cw_wire_read_u32(in + 4);
    uint32_t length = cw_wire_read_u32(in + 8);

    if (version != CW_WIRE_VERSION) {
        if (err) *err = CW_ERR_PROTOCOL;
        return CW_WIRE_ERROR;
    }
    if (!cw_wire_is_control(type) && !cw_wire_is_data(type)) {
        if (err) *err = CW_ERR_PROTOCOL;
        return CW_WIRE_ERROR;
    }
    if (length > CW_WIRE_FRAME_MAX) {
        if (err) *err = CW_ERR_FRAME_TOO_BIG;
        return CW_WIRE_ERROR;
    }
    if (!length_ok(type, length) || !stream_id_ok(type, sid)) {
        if (err) *err = CW_ERR_PROTOCOL;
        return CW_WIRE_ERROR;
    }
    if (len < (size_t)CW_WIRE_HDR + length)
        return CW_WIRE_NEED_MORE;

    frame->version = version;
    frame->type = type;
    frame->flags = flags;
    frame->stream_id = sid;
    frame->length = length;
    frame->payload = length ? in + CW_WIRE_HDR : NULL;
    if (consumed)
        *consumed = (size_t)CW_WIRE_HDR + length;
    return CW_WIRE_OK;
}

uint32_t cw_wire_backoff_ms(unsigned attempt, double rnd)
{
    uint64_t full = CW_WIRE_BACKOFF_BASE_MS;
    for (unsigned i = 0; i < attempt && full < CW_WIRE_BACKOFF_CAP_MS; i++)
        full <<= 1;
    if (full > CW_WIRE_BACKOFF_CAP_MS)
        full = CW_WIRE_BACKOFF_CAP_MS;
    if (rnd < 0.0)
        rnd = 0.0;
    if (rnd >= 1.0)
        rnd = 0.999999;
    uint32_t half = (uint32_t)(full / 2);
    uint32_t span = (uint32_t)(full - half);
    return half + (uint32_t)(rnd * (double)span);
}

int cw_wire_window_add(uint32_t *window, uint32_t credit)
{
    if (!window || credit > CW_WIRE_WINDOW_MAX)
        return -1;
    if (*window > CW_WIRE_WINDOW_MAX - credit)
        return -1;
    *window += credit;
    return 0;
}

int cw_wire_window_take(uint32_t *window, uint32_t n)
{
    if (!window || n > *window)
        return -1;
    *window -= n;
    return 0;
}
