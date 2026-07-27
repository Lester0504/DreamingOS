// SPDX-License-Identifier: GPL-2.0-or-later
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

struct ac_pki;
struct ac_pki_issued_certificate;

int ac_pki_init(struct ac_pki **out);
void ac_pki_free(struct ac_pki *pki);
const char *ac_pki_controller_id(const struct ac_pki *pki);
const char *ac_pki_ca_key_id(const struct ac_pki *pki);
const unsigned char *ac_pki_ca_fingerprint_sha256(const struct ac_pki *pki);
const char *ac_pki_ca_fingerprint_text(const struct ac_pki *pki);
X509 *ac_pki_ca_certificate_dup(const struct ac_pki *pki);
X509 *ac_pki_server_certificate_dup(const struct ac_pki *pki);
EVP_PKEY *ac_pki_server_private_key_dup(const struct ac_pki *pki);
int ac_pki_ca_der(const struct ac_pki *pki, unsigned char **out,
                  size_t *out_len);
int ac_pki_ca_pem(const struct ac_pki *pki, unsigned char **out,
                  size_t *out_len);
int ac_pki_issue_ap_certificate(
    const struct ac_pki *pki, const char *ap_id,
    const unsigned char raw_public_key[32],
    const unsigned char *csr_der, size_t csr_der_len,
    struct ac_pki_issued_certificate **out);
void ac_pki_issued_certificate_free(
    struct ac_pki_issued_certificate *certificate);
const unsigned char *ac_pki_issued_certificate_der(
    const struct ac_pki_issued_certificate *certificate, size_t *out_len);
X509 *ac_pki_issued_certificate_x509_dup(
    const struct ac_pki_issued_certificate *certificate);
const char *ac_pki_issued_certificate_serial(
    const struct ac_pki_issued_certificate *certificate);
const char *ac_pki_issued_certificate_issuer_key_id(
    const struct ac_pki_issued_certificate *certificate);
const unsigned char *ac_pki_issued_certificate_fingerprint_sha256(
    const struct ac_pki_issued_certificate *certificate);
const char *ac_pki_issued_certificate_fingerprint_text(
    const struct ac_pki_issued_certificate *certificate);
int64_t ac_pki_issued_certificate_not_before(
    const struct ac_pki_issued_certificate *certificate);
int64_t ac_pki_issued_certificate_not_after(
    const struct ac_pki_issued_certificate *certificate);

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define AP_ID "12345678-1234-4abc-8def-123456789abc"

static int write_full(int fd, const unsigned char *data, size_t len)
{
    size_t offset = 0;

    while (offset < len) {
        ssize_t written = write(fd, data + offset, len - offset);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return -1;
        offset += (size_t)written;
    }
    return 0;
}

static int write_bytes(const char *path, const unsigned char *data, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    int rc = -1;

    if (fd >= 0 && fchmod(fd, 0600) == 0 &&
        write_full(fd, data, len) == 0 && fsync(fd) == 0)
        rc = 0;
    if (fd >= 0 && close(fd) != 0)
        rc = -1;
    return rc;
}

static int write_x509_pem(const char *path, X509 *certificate)
{
    BIO *bio = NULL;
    BUF_MEM *memory = NULL;
    int rc = -1;

    bio = BIO_new(BIO_s_mem());
    if (!bio || PEM_write_bio_X509(bio, certificate) != 1)
        goto done;
    BIO_get_mem_ptr(bio, &memory);
    if (memory && memory->data && memory->length &&
        write_bytes(path, (const unsigned char *)memory->data,
                    memory->length) == 0)
        rc = 0;
done:
    BIO_free(bio);
    return rc;
}

static EVP_PKEY *key_generate(int rsa)
{
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY *key = NULL;

    context = EVP_PKEY_CTX_new_id(rsa ? EVP_PKEY_RSA : EVP_PKEY_ED25519, NULL);
    if (!context || EVP_PKEY_keygen_init(context) != 1 ||
        (rsa && EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) != 1) ||
        EVP_PKEY_keygen(context, &key) != 1) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static int request_add_san(X509_REQ *request, const char *uri,
                           int add_forbidden_extension)
{
    STACK_OF(X509_EXTENSION) *extensions = NULL;
    X509_EXTENSION *san = NULL;
    X509_EXTENSION *forbidden = NULL;
    char value[160];
    int rc = -1;

    if (snprintf(value, sizeof(value), "URI:%s", uri) >= (int)sizeof(value) ||
        !(extensions = sk_X509_EXTENSION_new_null()) ||
        !(san = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, value)) ||
        !sk_X509_EXTENSION_push(extensions, san))
        goto done;
    san = NULL;
    if (add_forbidden_extension) {
        forbidden = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
                                        "critical,CA:TRUE");
        if (!forbidden || !sk_X509_EXTENSION_push(extensions, forbidden))
            goto done;
        forbidden = NULL;
    }
    if (X509_REQ_add_extensions(request, extensions) == 1)
        rc = 0;
done:
    X509_EXTENSION_free(forbidden);
    X509_EXTENSION_free(san);
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
    return rc;
}

static int request_create(EVP_PKEY *key, const char *uri,
                          int forbidden_extension, int corrupt_signature,
                          unsigned char **out, size_t *out_len)
{
    X509_REQ *request = NULL;
    X509_NAME *subject;
    unsigned char *der = NULL;
    unsigned char *cursor;
    int der_len;
    int rc = -1;

    if (!(request = X509_REQ_new()) || X509_REQ_set_version(request, 0) != 1 ||
        X509_REQ_set_pubkey(request, key) != 1 ||
        request_add_san(request, uri, forbidden_extension) != 0 ||
        X509_REQ_sign(request, key,
                      EVP_PKEY_base_id(key) == EVP_PKEY_ED25519 ? NULL :
                      EVP_sha256()) <= 0)
        goto done;
    if (corrupt_signature) {
        subject = X509_REQ_get_subject_name(request);
        if (!subject || X509_NAME_add_entry_by_txt(
                subject, "CN", MBSTRING_ASC,
                (const unsigned char *)"tampered", -1, -1, 0) != 1)
            goto done;
    }
    der_len = i2d_X509_REQ(request, NULL);
    if (der_len <= 0 || !(der = OPENSSL_malloc((size_t)der_len)))
        goto done;
    cursor = der;
    if (i2d_X509_REQ(request, &cursor) != der_len)
        goto done;
    *out = der;
    *out_len = (size_t)der_len;
    der = NULL;
    rc = 0;
done:
    OPENSSL_free(der);
    X509_REQ_free(request);
    return rc;
}

static int inspect(void)
{
    struct ac_pki *pki = NULL;
    X509 *ca = NULL;
    X509 *server = NULL;
    EVP_PKEY *server_key = NULL;
    unsigned char *ca_der = NULL;
    unsigned char *ca_pem = NULL;
    size_t ca_der_len = 0;
    size_t ca_pem_len = 0;
    int rc = 2;

    if (ac_pki_init(&pki) != 0)
        goto done;
    ca = ac_pki_ca_certificate_dup(pki);
    server = ac_pki_server_certificate_dup(pki);
    server_key = ac_pki_server_private_key_dup(pki);
    if (!ca || !server || !server_key ||
        X509_check_private_key(server, server_key) != 1 ||
        ac_pki_ca_der(pki, &ca_der, &ca_der_len) != 0 ||
        ac_pki_ca_pem(pki, &ca_pem, &ca_pem_len) != 0 ||
        ca_der_len == 0 || ca_pem_len == 0)
        goto done;
    printf("controller_id=%s\nca_key_id=%s\nca_fingerprint=%s\n"
           "ca_der_len=%zu\nca_pem_len=%zu\n",
           ac_pki_controller_id(pki), ac_pki_ca_key_id(pki),
           ac_pki_ca_fingerprint_text(pki), ca_der_len, ca_pem_len);
    rc = 0;
done:
    OPENSSL_free(ca_der);
    OPENSSL_free(ca_pem);
    EVP_PKEY_free(server_key);
    X509_free(server);
    X509_free(ca);
    ac_pki_free(pki);
    return rc;
}

static int issue(const char *directory, const char *mode)
{
    struct ac_pki *pki = NULL;
    struct ac_pki_issued_certificate *issued = NULL;
    EVP_PKEY *ap_key = NULL;
    EVP_PKEY *passed_key = NULL;
    X509 *ca = NULL;
    X509 *server = NULL;
    X509 *client = NULL;
    unsigned char public_key[32] = {0};
    unsigned char passed_public[32] = {0};
    unsigned char *csr = NULL;
    unsigned char *ca_pem = NULL;
    const unsigned char *client_der;
    size_t public_len = sizeof(public_key);
    size_t passed_len = sizeof(passed_public);
    size_t csr_len = 0;
    size_t ca_pem_len = 0;
    size_t client_der_len = 0;
    char uri[96];
    char path[1024];
    int rsa = !strcmp(mode, "rsa");
    int expect_reject = strcmp(mode, "valid") != 0;
    int result;
    int rc = 2;

    if (mkdir(directory, 0700) != 0 && errno != EEXIST)
        goto done;
    if (ac_pki_init(&pki) != 0 || !(ap_key = key_generate(rsa)) ||
        snprintf(uri, sizeof(uri), "urn:dreamingwrt:ap:%s",
                 !strcmp(mode, "bad-san") ?
                 "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" : AP_ID) >=
            (int)sizeof(uri) ||
        request_create(ap_key, uri, !strcmp(mode, "extra-extension"),
                       !strcmp(mode, "bad-signature"), &csr, &csr_len) != 0)
        goto done;
    if (!rsa && EVP_PKEY_get_raw_public_key(ap_key, public_key,
                                            &public_len) != 1)
        goto done;
    if (rsa)
        memset(public_key, 0x42, sizeof(public_key));
    if (!strcmp(mode, "wrong-key")) {
        passed_key = key_generate(0);
        if (!passed_key || EVP_PKEY_get_raw_public_key(
                passed_key, passed_public, &passed_len) != 1 ||
            passed_len != sizeof(passed_public))
            goto done;
    } else {
        memcpy(passed_public, public_key, sizeof(public_key));
    }
    result = ac_pki_issue_ap_certificate(pki, AP_ID, passed_public,
                                         csr, csr_len, &issued);
    if (expect_reject) {
        printf("rejected=%s\n", result != 0 && !issued ? "true" : "false");
        rc = result != 0 && !issued ? 0 : 3;
        goto done;
    }
    if (result != 0 || !issued ||
        !(client_der = ac_pki_issued_certificate_der(issued,
                                                      &client_der_len)) ||
        !client_der_len || !(ca = ac_pki_ca_certificate_dup(pki)) ||
        !(server = ac_pki_server_certificate_dup(pki)) ||
        !(client = ac_pki_issued_certificate_x509_dup(issued)) ||
        X509_check_private_key(client, ap_key) != 1 ||
        ac_pki_ca_pem(pki, &ca_pem, &ca_pem_len) != 0)
        goto done;
    snprintf(path, sizeof(path), "%s/ca.pem", directory);
    if (write_bytes(path, ca_pem, ca_pem_len) != 0)
        goto done;
    snprintf(path, sizeof(path), "%s/server.pem", directory);
    if (write_x509_pem(path, server) != 0)
        goto done;
    snprintf(path, sizeof(path), "%s/client.pem", directory);
    if (write_x509_pem(path, client) != 0)
        goto done;
    snprintf(path, sizeof(path), "%s/client.der", directory);
    if (write_bytes(path, client_der, client_der_len) != 0)
        goto done;
    printf("controller_id=%s\nca_fingerprint=%s\nserial=%s\n"
           "issuer_key_id=%s\nclient_fingerprint=%s\n"
           "not_before=%lld\nnot_after=%lld\n",
           ac_pki_controller_id(pki), ac_pki_ca_fingerprint_text(pki),
           ac_pki_issued_certificate_serial(issued),
           ac_pki_issued_certificate_issuer_key_id(issued),
           ac_pki_issued_certificate_fingerprint_text(issued),
           (long long)ac_pki_issued_certificate_not_before(issued),
           (long long)ac_pki_issued_certificate_not_after(issued));
    rc = 0;
done:
    OPENSSL_cleanse(public_key, sizeof(public_key));
    OPENSSL_cleanse(passed_public, sizeof(passed_public));
    OPENSSL_free(ca_pem);
    OPENSSL_free(csr);
    X509_free(client);
    X509_free(server);
    X509_free(ca);
    EVP_PKEY_free(passed_key);
    EVP_PKEY_free(ap_key);
    ac_pki_issued_certificate_free(issued);
    ac_pki_free(pki);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "inspect"))
        return inspect();
    if (argc == 4 && !strcmp(argv[1], "issue"))
        return issue(argv[2], argv[3]);
    fprintf(stderr, "usage: %s inspect | issue OUTPUT valid|bad-signature|bad-san|wrong-key|extra-extension|rsa\n",
            argv[0]);
    return 64;
}
