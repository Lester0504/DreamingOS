// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_APD_PAIRCODE_H
#define DREAMINGWRT_APD_PAIRCODE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Pasteable pairing codes.
 *
 * Two distinct artifacts, deliberately not interchangeable:
 *
 *   DWRTAP1.<base32 payload>.<crc>   AP announcement, printed by the AP.
 *                                    Identity and connection info only.
 *   DWRTCT1.<base32 payload>.<crc>   Controller bootstrap, issued by the
 *                                    controller, consumed by `apdctl pair`.
 *                                    Carries the enrollment token.
 *
 * The split matters: the AP code is meant to be pasted into a browser and
 * may end up in clipboards and chat logs, so it must never carry anything
 * that alone permits adoption. Trust is still established by CSR/mTLS. The
 * controller code does carry a token, so it is treated as a secret and is
 * never printed as a QR or echoed back after use.
 *
 * Encoding: uppercase base32 (RFC 4648, no padding) over a versioned
 * TLV-ish payload, then a CRC-32 rendered as 7 uppercase base32 chars. No
 * spaces, so a double-click selects the whole thing, and the checksum lets
 * the web UI reject a truncated paste immediately instead of failing later
 * with a vague error.
 */

#define APD_PAIRCODE_AP_PREFIX "DWRTAP1"
#define APD_PAIRCODE_CT_PREFIX "DWRTCT1"
#define APD_PAIRCODE_MAX 512
/*
 * Longest AP code that still renders as a QR. v10-M alphanumeric holds 311
 * characters, so a code above that is text-only. Callers that want a
 * scannable code keep the payload lean: identity plus connection info, and
 * they let the controller look up model strings from the ap_id.
 */
#define APD_PAIRCODE_QR_MAX 311
#define APD_PAIRCODE_MAC_MAX 17
#define APD_PAIRCODE_MODEL_MAX 64
#define APD_PAIRCODE_BOARD_MAX 64
#define APD_PAIRCODE_HOST_MAX 253
#define APD_PAIRCODE_ID_MAX 36
#define APD_PAIRCODE_FPR_MAX 71
#define APD_PAIRCODE_SITE_MAX 64
#define APD_PAIRCODE_TOKEN_MAX 43

/* AP announcement payload. Contains no credential of any kind. */
struct apd_paircode_ap {
    int schema;
    char ap_id[APD_PAIRCODE_ID_MAX + 1];
    char key_id[APD_PAIRCODE_FPR_MAX + 1];
    char mac[APD_PAIRCODE_MAC_MAX + 1];
    char model[APD_PAIRCODE_MODEL_MAX + 1];
    char board_name[APD_PAIRCODE_BOARD_MAX + 1];
    char mgmt_ip[APD_PAIRCODE_HOST_MAX + 1];
    uint16_t mgmt_port;
};

/*
 * Field selection for encoding. The full form is for display and paste;
 * APD_PAIRCODE_FORM_COMPACT drops the descriptive strings so the result
 * stays inside QR range. ap_id, key_id, mac and the management endpoint
 * are always included -- those are what the controller actually needs.
 */
enum apd_paircode_form {
    APD_PAIRCODE_FORM_FULL = 0,
    APD_PAIRCODE_FORM_COMPACT = 1,
};

/* Controller bootstrap payload. Carries a token; treat as secret. */
struct apd_paircode_controller {
    int schema;
    char controller_host[APD_PAIRCODE_HOST_MAX + 1];
    uint16_t controller_port;
    char controller_id[APD_PAIRCODE_ID_MAX + 1];
    char token_id[APD_PAIRCODE_ID_MAX + 1];
    char token[APD_PAIRCODE_TOKEN_MAX + 1];
    char site_id[APD_PAIRCODE_SITE_MAX + 1];
};

enum apd_paircode_result {
    APD_PAIRCODE_OK = 0,
    APD_PAIRCODE_ERR_ARG = -1,
    APD_PAIRCODE_ERR_PREFIX = -2,      /* not a DreamingWrt pairing code */
    APD_PAIRCODE_ERR_FORMAT = -3,      /* structurally malformed */
    APD_PAIRCODE_ERR_CHECKSUM = -4,    /* truncated or mistyped */
    APD_PAIRCODE_ERR_SCHEMA = -5,      /* newer code than we understand */
    APD_PAIRCODE_ERR_FIELD = -6,       /* a field failed validation */
    APD_PAIRCODE_ERR_SPACE = -7,       /* output buffer too small */
};

const char *apd_paircode_strerror(int result);

int apd_paircode_ap_encode(const struct apd_paircode_ap *in,
                           char *out, size_t out_size);
int apd_paircode_ap_encode_form(const struct apd_paircode_ap *in,
                                enum apd_paircode_form form,
                                char *out, size_t out_size);
int apd_paircode_ap_decode(const char *text, struct apd_paircode_ap *out);

int apd_paircode_controller_encode(const struct apd_paircode_controller *in,
                                   char *out, size_t out_size);
int apd_paircode_controller_decode(const char *text,
                                   struct apd_paircode_controller *out);

/*
 * Normalizes a pasted code in place: strips surrounding whitespace, any
 * embedded newlines a terminal copy dragged along, and uppercases the body.
 * Returns the normalized length.
 */
size_t apd_paircode_normalize(char *text);

/* Short human-readable fingerprint, e.g. 3B44-0FD2-B882-D101, for the
 * operator to compare against what the web UI shows. */
void apd_paircode_fingerprint_short(const char *key_id, char *out,
                                    size_t out_size);

/* Scrubs a controller payload; call once the token has been consumed. */
void apd_paircode_controller_cleanse(struct apd_paircode_controller *value);

#endif
