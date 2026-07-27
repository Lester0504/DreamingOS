// SPDX-License-Identifier: GPL-2.0-or-later
#include "ac_enrollment_fixture.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define CROSS_TRANSCRIPT_MAX 1024
#define CROSS_DOMAIN "dreamingwrt-ap-enrollment-v1"

struct cross_field {
    const unsigned char *data;
    size_t len;
};

static int g_claim_called;

int ac_db_enrollment_claim(const struct ac_enrollment_claim *claim,
                           struct ac_enrollment_record *out)
{
    if (!claim || !out)
        return AC_ENROLLMENT_ERROR;
    g_claim_called++;
    memset(out, 0, sizeof(*out));
    snprintf(out->enrollment_id, sizeof(out->enrollment_id), "%s",
             claim->enrollment_id);
    return AC_ENROLLMENT_OK;
}

static int cross_read(const char *path, unsigned char *out, size_t capacity,
                      size_t *out_len)
{
    struct stat st;
    size_t offset = 0;
    int fd = -1;

    if (!path || !out || !out_len ||
        (fd = open(path, O_RDONLY | O_NOFOLLOW)) < 0 ||
        fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_size <= 0 || (uint64_t)st.st_size > capacity) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    while (offset < (size_t)st.st_size) {
        ssize_t count = read(fd, out + offset, (size_t)st.st_size - offset);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            close(fd);
            return -1;
        }
        offset += (size_t)count;
    }
    close(fd);
    *out_len = offset;
    return 0;
}

static int cross_parse(const unsigned char *raw, size_t raw_len,
                       struct cross_field fields[12], uint64_t *expires_at)
{
    static const unsigned char domain[] = CROSS_DOMAIN;
    size_t offset = sizeof(domain) - 1;
    size_t i;

    if (!raw || !fields || !expires_at || raw_len < offset + 12 * 2 + 8 ||
        CRYPTO_memcmp(raw, domain, offset) != 0)
        return -1;
    for (i = 0; i < 12; i++) {
        size_t len;

        if (raw_len - offset < 2)
            return -1;
        len = ((size_t)raw[offset] << 8) | raw[offset + 1];
        offset += 2;
        if (len > raw_len - offset)
            return -1;
        fields[i].data = raw + offset;
        fields[i].len = len;
        offset += len;
    }
    if (raw_len - offset != 8)
        return -1;
    *expires_at = 0;
    for (i = 0; i < 8; i++)
        *expires_at = (*expires_at << 8) | raw[offset + i];
    return 0;
}

static int cross_text(char *out, size_t capacity,
                      const struct cross_field *field)
{
    if (!out || !field || field->len == 0 || field->len >= capacity ||
        memchr(field->data, '\0', field->len))
        return -1;
    memcpy(out, field->data, field->len);
    out[field->len] = '\0';
    return 0;
}

int main(int argc, char **argv)
{
    struct ac_enrollment_signed_request request;
    struct ac_enrollment_record record;
    struct cross_field fields[12];
    unsigned char transcript[CROSS_TRANSCRIPT_MAX] = {0};
    unsigned char signature[AC_ENROLLMENT_SIGNATURE_LEN] = {0};
    unsigned char csr[AC_ENROLLMENT_CSR_MAX] = {0};
    char token[AC_PAIRING_TOKEN_LEN + 1] = {0};
    unsigned char *rebuilt = NULL;
    size_t transcript_len = 0;
    size_t signature_len = 0;
    size_t csr_len = 0;
    size_t rebuilt_len = 0;
    uint64_t expires_at = 0;
    int rc = 1;

    memset(&request, 0, sizeof(request));
    memset(&record, 0, sizeof(record));
    memset(fields, 0, sizeof(fields));
    if (argc != 4 ||
        cross_read(argv[1], transcript, sizeof(transcript),
                   &transcript_len) != 0 ||
        cross_read(argv[2], signature, sizeof(signature), &signature_len) != 0 ||
        cross_read(argv[3], csr, sizeof(csr), &csr_len) != 0 ||
        signature_len != sizeof(request.signature) ||
        cross_parse(transcript, transcript_len, fields, &expires_at) != 0 ||
        cross_text(request.claim.challenge_id,
                   sizeof(request.claim.challenge_id), &fields[0]) != 0 ||
        fields[1].len != sizeof(request.claim.server_nonce) ||
        fields[2].len != sizeof(request.claim.client_nonce) ||
        cross_text(request.claim.enrollment_id,
                   sizeof(request.claim.enrollment_id), &fields[3]) != 0 ||
        cross_text(request.claim.token_id,
                   sizeof(request.claim.token_id), &fields[4]) != 0 ||
        fields[5].len != AC_PAIRING_TOKEN_LEN ||
        cross_text(request.claim.ap_id, sizeof(request.claim.ap_id),
                   &fields[6]) != 0 ||
        cross_text(request.claim.key_id, sizeof(request.claim.key_id),
                   &fields[7]) != 0 ||
        fields[8].len != sizeof(request.claim.public_key) ||
        fields[9].len > AC_PAIRING_SITE_ID_LEN ||
        fields[10].len > AC_PAIRING_HARDWARE_DIGEST_LEN ||
        fields[11].len != sizeof(request.claim.csr_sha256))
        goto done;
    memcpy(request.claim.server_nonce, fields[1].data, fields[1].len);
    memcpy(request.claim.client_nonce, fields[2].data, fields[2].len);
    memcpy(token, fields[5].data, fields[5].len);
    request.claim.token = token;
    memcpy(request.claim.public_key, fields[8].data, fields[8].len);
    memcpy(request.claim.site_id, fields[9].data, fields[9].len);
    memcpy(request.claim.hardware_digest, fields[10].data, fields[10].len);
    memcpy(request.claim.csr_sha256, fields[11].data, fields[11].len);
    request.claim.csr_der = csr;
    request.claim.csr_der_len = csr_len;
    request.claim.challenge_expires_at = (int64_t)expires_at;
    memcpy(request.signature, signature, sizeof(request.signature));
    if (ac_enrollment_transcript_build(&request.claim, &rebuilt,
                                       &rebuilt_len) != 0 ||
        rebuilt_len != transcript_len ||
        CRYPTO_memcmp(rebuilt, transcript, transcript_len) != 0 ||
        ac_enrollment_verify_and_claim(&request, &record) != AC_ENROLLMENT_OK ||
        g_claim_called != 1 ||
        strcmp(record.enrollment_id, request.claim.enrollment_id) != 0)
        goto done;
    puts("ok: AC accepted APD transcript, CSR, public key, and signature");
    rc = 0;
done:
    if (rebuilt) {
        OPENSSL_cleanse(rebuilt, rebuilt_len);
        OPENSSL_free(rebuilt);
    }
    OPENSSL_cleanse(&request, sizeof(request));
    OPENSSL_cleanse(&record, sizeof(record));
    OPENSSL_cleanse(transcript, sizeof(transcript));
    OPENSSL_cleanse(signature, sizeof(signature));
    OPENSSL_cleanse(csr, sizeof(csr));
    OPENSSL_cleanse(token, sizeof(token));
    return rc;
}
