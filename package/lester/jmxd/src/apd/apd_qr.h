// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_APD_QR_H
#define DREAMINGWRT_APD_QR_H

#include <stdio.h>

/*
 * Self-contained QR encoder, alphanumeric mode, ECC level M, versions 1-10.
 *
 * apd runs on APs that do not ship qrencode, so shelling out is not an
 * option here (webd does that for TOTP, where a browser is present). Scope
 * is deliberately narrow: the pairing codes this renders are uppercase
 * base32 plus '.', which is entirely inside the QR alphanumeric charset,
 * and v10 at level M holds 311 such characters -- well past what a pairing
 * code needs.
 */

#define APD_QR_MIN_VERSION 1
#define APD_QR_MAX_VERSION 10
/* 4 * 10 + 17 */
#define APD_QR_MAX_SIZE 57
#define APD_QR_QUIET_DEFAULT 2

struct apd_qr {
    int version;
    int size;
    int mask;
    unsigned char module[APD_QR_MAX_SIZE][APD_QR_MAX_SIZE];
};

enum apd_qr_result {
    APD_QR_OK = 0,
    APD_QR_ERR_ARG = -1,
    APD_QR_ERR_CHARSET = -2,
    APD_QR_ERR_TOO_LONG = -3,
};

/* Returns APD_QR_OK, or a negative enum apd_qr_result. */
int apd_qr_encode_alnum(const char *text, struct apd_qr *out);

/* 1 = every character is representable in QR alphanumeric mode. */
int apd_qr_alnum_compatible(const char *text);

/*
 * Terminal columns a half-block render occupies: one column per module plus
 * the quiet zone on both sides. Callers compare this against the real
 * terminal width and fall back to text when it will not fit, rather than
 * printing a wrapped matrix nothing can scan.
 */
int apd_qr_render_columns(const struct apd_qr *qr, int quiet);
int apd_qr_render_rows(const struct apd_qr *qr, int quiet);

/*
 * Half-block render, two module rows per text line. color forces black-on-
 * white via ANSI so polarity is right on both light and dark terminals;
 * without it the caller is trusting the terminal to be light-themed.
 */
void apd_qr_render_halfblock(const struct apd_qr *qr, int quiet, int color,
                             FILE *out);

#endif
