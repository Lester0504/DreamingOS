// SPDX-License-Identifier: GPL-2.0-or-later
#ifdef AC_PKI_TEST_STANDALONE
#include <stdint.h>
#include <stddef.h>
#else
#include "ac_internal.h"
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifndef O_DIRECTORY
#error "dreamingwrt-ac PKI requires O_DIRECTORY"
#endif
#ifndef O_NOFOLLOW
#error "dreamingwrt-ac PKI requires O_NOFOLLOW"
#endif

#define AC_PKI_DEFAULT_DIR "/etc/dreamingwrt/ac-pki"
#define AC_PKI_CA_KEY_FILE "ca.ed25519"
#define AC_PKI_CA_CERT_FILE "ca.crt.der"
#define AC_PKI_SERVER_KEY_FILE "server.ed25519"
#define AC_PKI_SERVER_CERT_FILE "server.crt.der"
#define AC_PKI_LOCK_FILE "init.lock"
#define AC_PKI_ED25519_KEY_LEN 32
#define AC_PKI_FINGERPRINT_LEN SHA256_DIGEST_LENGTH
#define AC_PKI_KEY_ID_LEN 71
#define AC_PKI_CONTROLLER_ID_LEN 36
#define AC_PKI_MAX_CERT_DER 32768
#define AC_PKI_MAX_CSR_DER 8192
#define AC_PKI_MAX_LISTEN_NAMES 32
#define AC_PKI_MAX_LISTEN_NAME_LEN 253
#define AC_PKI_CA_LIFETIME ((int64_t)10 * 365 * 24 * 60 * 60)
#define AC_PKI_SERVER_LIFETIME ((int64_t)825 * 24 * 60 * 60)
#define AC_PKI_CLIENT_LIFETIME ((int64_t)90 * 24 * 60 * 60)
#define AC_PKI_CLOCK_SKEW 900

struct ac_pki {
    char directory[1024];
    char controller_id[AC_PKI_CONTROLLER_ID_LEN + 1];
    char ca_key_id[AC_PKI_KEY_ID_LEN + 1];
    char ca_fingerprint_text[AC_PKI_KEY_ID_LEN + 1];
    unsigned char ca_fingerprint[AC_PKI_FINGERPRINT_LEN];
    EVP_PKEY *ca_key;
    X509 *ca_cert;
    EVP_PKEY *server_key;
    X509 *server_cert;
};

struct ac_pki_issued_certificate {
    X509 *certificate;
    unsigned char *der;
    size_t der_len;
    char serial[129];
    char issuer_key_id[AC_PKI_KEY_ID_LEN + 1];
    unsigned char fingerprint[AC_PKI_FINGERPRINT_LEN];
    char fingerprint_text[AC_PKI_KEY_ID_LEN + 1];
    int64_t not_before;
    int64_t not_after;
};

enum ac_pki_name_type {
    AC_PKI_NAME_DNS,
    AC_PKI_NAME_IP,
};

struct ac_pki_name {
    enum ac_pki_name_type type;
    char text[AC_PKI_MAX_LISTEN_NAME_LEN + 1];
    unsigned char address[16];
    size_t address_len;
};

struct ac_pki_name_list {
    struct ac_pki_name values[AC_PKI_MAX_LISTEN_NAMES];
    size_t count;
};

static int ac_pki_write_full(int fd, const unsigned char *data, size_t len)
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

static int ac_pki_read_full(int fd, unsigned char *data, size_t len)
{
    size_t offset = 0;

    while (offset < len) {
        ssize_t count = read(fd, data + offset, len - offset);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        offset += (size_t)count;
    }
    return 0;
}

static void ac_pki_hex(char *out, size_t out_size,
                       const unsigned char *data, size_t data_len)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    if (!out || out_size < data_len * 2 + 1)
        return;
    for (i = 0; i < data_len; i++) {
        out[i * 2] = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 15];
    }
    out[data_len * 2] = '\0';
}

static int ac_pki_owner_secure(uid_t owner)
{
    return owner == geteuid();
}

static int ac_pki_split_path(const char *path, char *parent,
                             size_t parent_size, const char **base)
{
    const char *slash;
    size_t parent_len;

    if (!path || path[0] != '/' || !parent || !base ||
        !(slash = strrchr(path, '/')) || slash == path || !slash[1])
        return -1;
    parent_len = (size_t)(slash - path);
    if (parent_len >= parent_size)
        return -1;
    memcpy(parent, path, parent_len);
    parent[parent_len] = '\0';
    *base = slash + 1;
    return 0;
}

static int ac_pki_sync_directory(int dirfd)
{
    return fsync(dirfd) == 0 ? 0 : -1;
}

static int ac_pki_prepare_directory(const char *path)
{
    char parent[1024];
    const char *base = NULL;
    struct stat parent_st;
    struct stat pki_st;
    int parent_fd = -1;
    int pki_fd = -1;
    int rc = -1;

    if (ac_pki_split_path(path, parent, sizeof(parent), &base) != 0 ||
        lstat(parent, &parent_st) != 0 || !S_ISDIR(parent_st.st_mode) ||
        !ac_pki_owner_secure(parent_st.st_uid) ||
        (parent_st.st_mode & 0022) != 0)
        return -1;
    parent_fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (parent_fd < 0 || fstat(parent_fd, &parent_st) != 0 ||
        !S_ISDIR(parent_st.st_mode) ||
        !ac_pki_owner_secure(parent_st.st_uid) ||
        (parent_st.st_mode & 0022) != 0)
        goto done;
    if (mkdirat(parent_fd, base, 0700) != 0 && errno != EEXIST)
        goto done;
    if (ac_pki_sync_directory(parent_fd) != 0)
        goto done;
    pki_fd = openat(parent_fd, base, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (pki_fd < 0 || fstat(pki_fd, &pki_st) != 0 ||
        !S_ISDIR(pki_st.st_mode) || !ac_pki_owner_secure(pki_st.st_uid) ||
        (pki_st.st_mode & 0777) != 0700)
        goto done;
    rc = pki_fd;
    pki_fd = -1;
done:
    if (pki_fd >= 0)
        close(pki_fd);
    if (parent_fd >= 0)
        close(parent_fd);
    return rc;
}

static int ac_pki_file_status(int dirfd, const char *name, off_t exact_size,
                              off_t maximum_size)
{
    struct stat st;

    if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        !ac_pki_owner_secure(st.st_uid) || (st.st_mode & 0777) != 0600 ||
        (exact_size >= 0 && st.st_size != exact_size) ||
        (maximum_size >= 0 && (st.st_size <= 0 || st.st_size > maximum_size)))
        return -1;
    return 1;
}

static int ac_pki_read_file(int dirfd, const char *name, off_t exact_size,
                            off_t maximum_size, unsigned char **out,
                            size_t *out_len)
{
    struct stat before = {0};
    struct stat after = {0};
    unsigned char *data = NULL;
    unsigned char extra;
    int fd = -1;
    int status;
    int rc = -1;

    if (!out || !out_len)
        return -1;
    *out = NULL;
    *out_len = 0;
    status = ac_pki_file_status(dirfd, name, exact_size, maximum_size);
    if (status != 1)
        return status == 0 ? 1 : -1;
    fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_nlink != 1 || !ac_pki_owner_secure(before.st_uid) ||
        (before.st_mode & 0777) != 0600 || before.st_size <= 0 ||
        (exact_size >= 0 && before.st_size != exact_size) ||
        (maximum_size >= 0 && before.st_size > maximum_size) ||
        (uintmax_t)before.st_size > SIZE_MAX)
        goto done;
    data = OPENSSL_malloc((size_t)before.st_size);
    if (!data || ac_pki_read_full(fd, data, (size_t)before.st_size) != 0 ||
        read(fd, &extra, 1) != 0 || fstat(fd, &after) != 0 ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || before.st_mode != after.st_mode ||
        before.st_uid != after.st_uid || before.st_nlink != after.st_nlink)
        goto done;
    *out = data;
    *out_len = (size_t)before.st_size;
    data = NULL;
    rc = 0;
done:
    if (fd >= 0)
        close(fd);
    if (data) {
        OPENSSL_cleanse(data, (size_t)(before.st_size > 0 ? before.st_size : 0));
        OPENSSL_free(data);
    }
    OPENSSL_cleanse(&extra, sizeof(extra));
    return rc;
}

static int ac_pki_atomic_write(int dirfd, const char *name,
                               const unsigned char *data, size_t len)
{
    unsigned char random[8] = {0};
    char temporary[160] = {0};
    struct stat st;
    int fd = -1;
    int rc = -1;

    if (!name || !data || len == 0 ||
        RAND_bytes(random, sizeof(random)) != 1 ||
        snprintf(temporary, sizeof(temporary), ".%s.tmp.%ld.%02x%02x%02x%02x%02x%02x%02x%02x",
                 name, (long)getpid(), random[0], random[1], random[2], random[3],
                 random[4], random[5], random[6], random[7]) >=
            (int)sizeof(temporary))
        goto done;
    if (ac_pki_file_status(dirfd, name, -1, -1) != 0) {
        errno = EEXIST;
        goto done;
    }
    fd = openat(dirfd, temporary,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_nlink != 1 || !ac_pki_owner_secure(st.st_uid) ||
        fchmod(fd, 0600) != 0 || ac_pki_write_full(fd, data, len) != 0 ||
        fsync(fd) != 0)
        goto done;
    if (close(fd) != 0) {
        fd = -1;
        goto done;
    }
    fd = -1;
    if (ac_pki_file_status(dirfd, name, -1, -1) != 0 ||
        renameat(dirfd, temporary, dirfd, name) != 0 ||
        ac_pki_sync_directory(dirfd) != 0 ||
        ac_pki_file_status(dirfd, name, (off_t)len, -1) != 1)
        goto done;
    rc = 0;
done:
    if (fd >= 0)
        close(fd);
    if (temporary[0])
        unlinkat(dirfd, temporary, 0);
    OPENSSL_cleanse(random, sizeof(random));
    return rc;
}

static int ac_pki_atomic_replace(int dirfd, const char *name,
                                 const unsigned char *data, size_t len)
{
    unsigned char random[8] = {0};
    char temporary[160] = {0};
    struct stat st;
    int fd = -1;
    int rc = -1;

    if (!name || !data || len == 0 ||
        ac_pki_file_status(dirfd, name, -1, AC_PKI_MAX_CERT_DER) != 1 ||
        RAND_bytes(random, sizeof(random)) != 1 ||
        snprintf(temporary, sizeof(temporary), ".%s.tmp.%ld.%02x%02x%02x%02x%02x%02x%02x%02x",
                 name, (long)getpid(), random[0], random[1], random[2], random[3],
                 random[4], random[5], random[6], random[7]) >=
            (int)sizeof(temporary))
        goto done;
    fd = openat(dirfd, temporary,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_nlink != 1 || !ac_pki_owner_secure(st.st_uid) ||
        fchmod(fd, 0600) != 0 || ac_pki_write_full(fd, data, len) != 0 ||
        fsync(fd) != 0)
        goto done;
    if (close(fd) != 0) {
        fd = -1;
        goto done;
    }
    fd = -1;
    if (ac_pki_file_status(dirfd, name, -1, AC_PKI_MAX_CERT_DER) != 1 ||
        renameat(dirfd, temporary, dirfd, name) != 0 ||
        ac_pki_sync_directory(dirfd) != 0 ||
        ac_pki_file_status(dirfd, name, (off_t)len, -1) != 1)
        goto done;
    rc = 0;
done:
    if (fd >= 0)
        close(fd);
    if (temporary[0])
        unlinkat(dirfd, temporary, 0);
    OPENSSL_cleanse(random, sizeof(random));
    return rc;
}

static int ac_pki_lock(int dirfd)
{
    struct stat st;
    int fd;
    int lock_rc;
    int stat_rc;

    do {
        fd = openat(dirfd, AC_PKI_LOCK_FILE,
                    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0 && errno == EEXIST) {
        do {
            fd = openat(dirfd, AC_PKI_LOCK_FILE,
                        O_RDWR | O_NOFOLLOW);
        } while (fd < 0 && errno == EINTR);
    }
    do {
        lock_rc = fd >= 0 ? flock(fd, LOCK_EX) : -1;
    } while (lock_rc != 0 && errno == EINTR);
    memset(&st, 0, sizeof(st));
    stat_rc = fd >= 0 ? fstat(fd, &st) : -1;
    if (fd < 0 || stat_rc != 0 || !S_ISREG(st.st_mode) ||
        st.st_nlink != 1 || !ac_pki_owner_secure(st.st_uid) ||
        (st.st_mode & 0777) != 0600 || lock_rc != 0) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    return fd;
}

static void ac_pki_unlock(int fd)
{
    if (fd >= 0) {
        flock(fd, LOCK_UN);
        close(fd);
    }
}

static EVP_PKEY *ac_pki_key_generate(void)
{
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY *key = NULL;

    context = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!context || EVP_PKEY_keygen_init(context) != 1 ||
        EVP_PKEY_keygen(context, &key) != 1) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static int ac_pki_key_raw_private(EVP_PKEY *key,
                                  unsigned char out[AC_PKI_ED25519_KEY_LEN])
{
    size_t len = AC_PKI_ED25519_KEY_LEN;

    return key && EVP_PKEY_base_id(key) == EVP_PKEY_ED25519 &&
        EVP_PKEY_get_raw_private_key(key, out, &len) == 1 &&
        len == AC_PKI_ED25519_KEY_LEN ? 0 : -1;
}

static EVP_PKEY *ac_pki_key_from_raw(const unsigned char *raw, size_t len)
{
    if (!raw || len != AC_PKI_ED25519_KEY_LEN)
        return NULL;
    return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, raw, len);
}

static int ac_pki_public_raw(EVP_PKEY *key,
                             unsigned char out[AC_PKI_ED25519_KEY_LEN])
{
    size_t len = AC_PKI_ED25519_KEY_LEN;

    return key && EVP_PKEY_base_id(key) == EVP_PKEY_ED25519 &&
        EVP_PKEY_get_raw_public_key(key, out, &len) == 1 &&
        len == AC_PKI_ED25519_KEY_LEN ? 0 : -1;
}

static int ac_pki_key_id(EVP_PKEY *key,
                         char out[AC_PKI_KEY_ID_LEN + 1],
                         unsigned char digest[AC_PKI_FINGERPRINT_LEN])
{
    unsigned char public_key[AC_PKI_ED25519_KEY_LEN] = {0};
    char hex[AC_PKI_FINGERPRINT_LEN * 2 + 1] = {0};
    int rc = -1;

    if (ac_pki_public_raw(key, public_key) != 0 ||
        !SHA256(public_key, sizeof(public_key), digest))
        goto done;
    ac_pki_hex(hex, sizeof(hex), digest, AC_PKI_FINGERPRINT_LEN);
    if (snprintf(out, AC_PKI_KEY_ID_LEN + 1, "sha256:%s", hex) >=
        AC_PKI_KEY_ID_LEN + 1)
        goto done;
    rc = 0;
done:
    OPENSSL_cleanse(public_key, sizeof(public_key));
    OPENSSL_cleanse(hex, sizeof(hex));
    return rc;
}

static void ac_pki_controller_id_from_digest(
    const unsigned char digest[AC_PKI_FINGERPRINT_LEN],
    char out[AC_PKI_CONTROLLER_ID_LEN + 1])
{
    unsigned char value[16];

    memcpy(value, digest, sizeof(value));
    value[6] = (value[6] & 0x0f) | 0x50;
    value[8] = (value[8] & 0x3f) | 0x80;
    snprintf(out, AC_PKI_CONTROLLER_ID_LEN + 1,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             value[0], value[1], value[2], value[3], value[4], value[5],
             value[6], value[7], value[8], value[9], value[10], value[11],
             value[12], value[13], value[14], value[15]);
    OPENSSL_cleanse(value, sizeof(value));
}

static int ac_pki_serial_set(X509 *certificate)
{
    unsigned char raw[20] = {0};
    BIGNUM *number = NULL;
    ASN1_INTEGER *serial = NULL;
    int rc = -1;

    if (!certificate || RAND_bytes(raw, sizeof(raw)) != 1)
        goto done;
    raw[0] &= 0x7f;
    raw[0] |= 0x40;
    number = BN_bin2bn(raw, sizeof(raw), NULL);
    serial = number ? BN_to_ASN1_INTEGER(number, NULL) : NULL;
    if (serial && X509_set_serialNumber(certificate, serial) == 1)
        rc = 0;
done:
    ASN1_INTEGER_free(serial);
    BN_free(number);
    OPENSSL_cleanse(raw, sizeof(raw));
    return rc;
}

static int ac_pki_validity_set(X509 *certificate, int64_t lifetime,
                               int64_t *not_before, int64_t *not_after)
{
    time_t now = time(NULL);
    time_t before;
    time_t after;
    ASN1_TIME *before_asn1 = NULL;
    ASN1_TIME *after_asn1 = NULL;
    int rc = -1;

    if (!certificate || now <= 0 || lifetime <= AC_PKI_CLOCK_SKEW ||
        (int64_t)now > INT64_MAX - lifetime)
        return -1;
    before = now - AC_PKI_CLOCK_SKEW;
    after = (time_t)((int64_t)now + lifetime);
    before_asn1 = ASN1_TIME_set(NULL, before);
    after_asn1 = ASN1_TIME_set(NULL, after);
    if (before_asn1 && after_asn1 &&
        X509_set1_notBefore(certificate, before_asn1) == 1 &&
        X509_set1_notAfter(certificate, after_asn1) == 1) {
        if (not_before)
            *not_before = (int64_t)before;
        if (not_after)
            *not_after = (int64_t)after;
        rc = 0;
    }
    ASN1_TIME_free(before_asn1);
    ASN1_TIME_free(after_asn1);
    return rc;
}

static int ac_pki_name_set(X509_NAME *name, const char *common_name)
{
    return name && common_name &&
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                   (const unsigned char *)"DreamingWrt",
                                   -1, -1, 0) == 1 &&
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   (const unsigned char *)common_name,
                                   -1, -1, 0) == 1 ? 0 : -1;
}

static int ac_pki_extension_conf(X509 *certificate, X509 *issuer,
                                 int nid, const char *value)
{
    X509V3_CTX context;
    X509_EXTENSION *extension = NULL;
    int rc = -1;

    X509V3_set_ctx(&context, issuer, certificate, NULL, NULL, 0);
    extension = X509V3_EXT_conf_nid(NULL, &context, nid, (char *)value);
    if (extension && X509_add_ext(certificate, extension, -1) == 1)
        rc = 0;
    X509_EXTENSION_free(extension);
    return rc;
}

static int ac_pki_dns_valid(const char *value)
{
    size_t len;
    size_t label = 0;
    size_t i;

    if (!value || !(len = strlen(value)) || len > AC_PKI_MAX_LISTEN_NAME_LEN ||
        value[0] == '.' || value[len - 1] == '.')
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];

        if (c == '.') {
            if (!label || label > 63 || value[i - 1] == '-')
                return 0;
            label = 0;
        } else {
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '-') ||
                (!label && c == '-'))
                return 0;
            label++;
        }
    }
    return label > 0 && label <= 63 && value[len - 1] != '-';
}

static int ac_pki_name_equal(const struct ac_pki_name *left,
                             const struct ac_pki_name *right)
{
    if (left->type != right->type)
        return 0;
    if (left->type == AC_PKI_NAME_DNS)
        return strcasecmp(left->text, right->text) == 0;
    return left->address_len == right->address_len &&
        CRYPTO_memcmp(left->address, right->address,
                      left->address_len) == 0;
}

static int ac_pki_name_add(struct ac_pki_name_list *list, const char *input)
{
    struct ac_pki_name candidate;
    const char *value = input;
    size_t i;

    if (!list || !input || !input[0])
        return -1;
    memset(&candidate, 0, sizeof(candidate));
    if (!strncasecmp(value, "DNS:", 4)) {
        candidate.type = AC_PKI_NAME_DNS;
        value += 4;
    } else if (!strncasecmp(value, "IP:", 3)) {
        value += 3;
        candidate.type = AC_PKI_NAME_IP;
    } else if (inet_pton(AF_INET, value, candidate.address) == 1) {
        candidate.type = AC_PKI_NAME_IP;
        candidate.address_len = 4;
    } else if (inet_pton(AF_INET6, value, candidate.address) == 1) {
        candidate.type = AC_PKI_NAME_IP;
        candidate.address_len = 16;
    } else {
        candidate.type = AC_PKI_NAME_DNS;
    }
    if (candidate.type == AC_PKI_NAME_IP && candidate.address_len == 0) {
        if (inet_pton(AF_INET, value, candidate.address) == 1)
            candidate.address_len = 4;
        else if (inet_pton(AF_INET6, value, candidate.address) == 1)
            candidate.address_len = 16;
        else
            return -1;
    }
    if (candidate.type == AC_PKI_NAME_DNS) {
        if (!ac_pki_dns_valid(value))
            return -1;
        snprintf(candidate.text, sizeof(candidate.text), "%s", value);
    } else {
        snprintf(candidate.text, sizeof(candidate.text), "%s", value);
    }
    for (i = 0; i < list->count; i++)
        if (ac_pki_name_equal(&candidate, &list->values[i]))
            return 0;
    if (list->count >= AC_PKI_MAX_LISTEN_NAMES)
        return -1;
    list->values[list->count++] = candidate;
    return 0;
}

static int ac_pki_listen_names(struct ac_pki_name_list *list)
{
    const char *configured = getenv("DREAMINGWRT_AC_LISTEN_NAMES");
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *interface;
    char *copy = NULL;
    char *cursor;
    char *token;
    int rc = -1;

    if (!list)
        return -1;
    memset(list, 0, sizeof(*list));
    if (!configured || !configured[0]) {
        if (ac_pki_name_add(list, "localhost") != 0 ||
            ac_pki_name_add(list, "127.0.0.1") != 0 ||
            ac_pki_name_add(list, "::1") != 0 ||
            getifaddrs(&interfaces) != 0)
            return -1;
        for (interface = interfaces; interface; interface = interface->ifa_next) {
            char address[INET6_ADDRSTRLEN];
            const void *source = NULL;

            if (!interface->ifa_addr ||
                !(interface->ifa_flags & IFF_UP) ||
                (interface->ifa_flags & IFF_LOOPBACK))
                continue;
            if (interface->ifa_addr->sa_family == AF_INET)
                source = &((struct sockaddr_in *)interface->ifa_addr)->sin_addr;
            else if (interface->ifa_addr->sa_family == AF_INET6)
                source = &((struct sockaddr_in6 *)interface->ifa_addr)->sin6_addr;
            else
                continue;
            if (!inet_ntop(interface->ifa_addr->sa_family, source, address,
                           sizeof(address)) ||
                ac_pki_name_add(list, address) != 0) {
                freeifaddrs(interfaces);
                return -1;
            }
        }
        freeifaddrs(interfaces);
        return list->count > 3 ? 0 : -1;
    }
    copy = strdup(configured);
    if (!copy)
        return -1;
    cursor = copy;
    while ((token = strsep(&cursor, ",")) != NULL) {
        char *end;

        while (*token == ' ' || *token == '\t')
            token++;
        end = token + strlen(token);
        while (end > token && (end[-1] == ' ' || end[-1] == '\t'))
            *--end = '\0';
        if (!token[0] || ac_pki_name_add(list, token) != 0)
            goto done;
    }
    rc = list->count ? 0 : -1;
done:
    OPENSSL_cleanse(copy, copy ? strlen(copy) : 0);
    free(copy);
    return rc;
}

static GENERAL_NAMES *ac_pki_server_names_build(
    const char *controller_id, const struct ac_pki_name_list *listen_names)
{
    GENERAL_NAMES *names = NULL;
    GENERAL_NAME *name = NULL;
    ASN1_IA5STRING *ia5 = NULL;
    ASN1_OCTET_STRING *octets = NULL;
    char uri[96];
    size_t i;

    if (!controller_id || !listen_names ||
        snprintf(uri, sizeof(uri), "urn:dreamingwrt:ac:%s", controller_id) >=
            (int)sizeof(uri) || !(names = sk_GENERAL_NAME_new_null()))
        return NULL;
    name = GENERAL_NAME_new();
    ia5 = ASN1_IA5STRING_new();
    if (!name || !ia5 || !ASN1_STRING_set(ia5, uri, -1))
        goto fail;
    GENERAL_NAME_set0_value(name, GEN_URI, ia5);
    ia5 = NULL;
    if (!sk_GENERAL_NAME_push(names, name))
        goto fail;
    name = NULL;
    for (i = 0; i < listen_names->count; i++) {
        const struct ac_pki_name *source = &listen_names->values[i];

        name = GENERAL_NAME_new();
        if (!name)
            goto fail;
        if (source->type == AC_PKI_NAME_DNS) {
            ia5 = ASN1_IA5STRING_new();
            if (!ia5 || !ASN1_STRING_set(ia5, source->text, -1))
                goto fail;
            GENERAL_NAME_set0_value(name, GEN_DNS, ia5);
            ia5 = NULL;
        } else {
            octets = ASN1_OCTET_STRING_new();
            if (!octets || !ASN1_OCTET_STRING_set(octets, source->address,
                                                  (int)source->address_len))
                goto fail;
            GENERAL_NAME_set0_value(name, GEN_IPADD, octets);
            octets = NULL;
        }
        if (!sk_GENERAL_NAME_push(names, name))
            goto fail;
        name = NULL;
    }
    OPENSSL_cleanse(uri, sizeof(uri));
    return names;
fail:
    ASN1_IA5STRING_free(ia5);
    ASN1_OCTET_STRING_free(octets);
    GENERAL_NAME_free(name);
    GENERAL_NAMES_free(names);
    OPENSSL_cleanse(uri, sizeof(uri));
    return NULL;
}

static GENERAL_NAMES *ac_pki_ap_name_build(const char *ap_id)
{
    GENERAL_NAMES *names = NULL;
    GENERAL_NAME *name = NULL;
    ASN1_IA5STRING *ia5 = NULL;
    char uri[96];

    if (!ap_id || snprintf(uri, sizeof(uri), "urn:dreamingwrt:ap:%s", ap_id) >=
                      (int)sizeof(uri) ||
        !(names = sk_GENERAL_NAME_new_null()) || !(name = GENERAL_NAME_new()) ||
        !(ia5 = ASN1_IA5STRING_new()) || !ASN1_STRING_set(ia5, uri, -1))
        goto fail;
    GENERAL_NAME_set0_value(name, GEN_URI, ia5);
    ia5 = NULL;
    if (!sk_GENERAL_NAME_push(names, name))
        goto fail;
    OPENSSL_cleanse(uri, sizeof(uri));
    return names;
fail:
    ASN1_IA5STRING_free(ia5);
    GENERAL_NAME_free(name);
    GENERAL_NAMES_free(names);
    OPENSSL_cleanse(uri, sizeof(uri));
    return NULL;
}

static int ac_pki_san_add(X509 *certificate, GENERAL_NAMES *names)
{
    return certificate && names &&
        X509_add1_ext_i2d(certificate, NID_subject_alt_name, names, 0,
                          X509V3_ADD_DEFAULT) == 1 ? 0 : -1;
}

static X509 *ac_pki_ca_create(EVP_PKEY *key, const char *controller_id)
{
    X509 *certificate = NULL;
    X509_NAME *subject;
    char common_name[96];

    if (!key || !controller_id ||
        snprintf(common_name, sizeof(common_name),
                 "DreamingWrt Controller CA %s", controller_id) >=
            (int)sizeof(common_name) || !(certificate = X509_new()) ||
        X509_set_version(certificate, 2) != 1 ||
        ac_pki_serial_set(certificate) != 0 ||
        ac_pki_validity_set(certificate, AC_PKI_CA_LIFETIME, NULL, NULL) != 0 ||
        X509_set_pubkey(certificate, key) != 1 ||
        !(subject = X509_get_subject_name(certificate)) ||
        ac_pki_name_set(subject, common_name) != 0 ||
        X509_set_issuer_name(certificate, subject) != 1 ||
        ac_pki_extension_conf(certificate, certificate,
                              NID_basic_constraints,
                              "critical,CA:TRUE,pathlen:0") != 0 ||
        ac_pki_extension_conf(certificate, certificate, NID_key_usage,
                              "critical,keyCertSign,cRLSign") != 0 ||
        ac_pki_extension_conf(certificate, certificate,
                              NID_subject_key_identifier, "hash") != 0 ||
        ac_pki_extension_conf(certificate, certificate,
                              NID_authority_key_identifier,
                              "keyid:always") != 0 ||
        X509_sign(certificate, key, NULL) <= 0) {
        X509_free(certificate);
        certificate = NULL;
    }
    OPENSSL_cleanse(common_name, sizeof(common_name));
    return certificate;
}

static X509 *ac_pki_server_create(EVP_PKEY *server_key, X509 *ca_certificate,
                                  EVP_PKEY *ca_key, const char *controller_id,
                                  const struct ac_pki_name_list *listen_names)
{
    X509 *certificate = NULL;
    X509_NAME *subject;
    GENERAL_NAMES *names = NULL;
    char common_name[96];

    if (!server_key || !ca_certificate || !ca_key || !controller_id ||
        !listen_names ||
        snprintf(common_name, sizeof(common_name), "DreamingWrt AC %s",
                 controller_id) >= (int)sizeof(common_name) ||
        !(certificate = X509_new()) || X509_set_version(certificate, 2) != 1 ||
        ac_pki_serial_set(certificate) != 0 ||
        ac_pki_validity_set(certificate, AC_PKI_SERVER_LIFETIME,
                            NULL, NULL) != 0 ||
        X509_set_pubkey(certificate, server_key) != 1 ||
        !(subject = X509_get_subject_name(certificate)) ||
        ac_pki_name_set(subject, common_name) != 0 ||
        X509_set_issuer_name(certificate,
                             X509_get_subject_name(ca_certificate)) != 1 ||
        ac_pki_extension_conf(certificate, ca_certificate,
                              NID_basic_constraints,
                              "critical,CA:FALSE") != 0 ||
        ac_pki_extension_conf(certificate, ca_certificate, NID_key_usage,
                              "critical,digitalSignature") != 0 ||
        ac_pki_extension_conf(certificate, ca_certificate,
                              NID_ext_key_usage, "serverAuth") != 0 ||
        ac_pki_extension_conf(certificate, ca_certificate,
                              NID_subject_key_identifier, "hash") != 0 ||
        ac_pki_extension_conf(certificate, ca_certificate,
                              NID_authority_key_identifier,
                              "keyid:always") != 0 ||
        !(names = ac_pki_server_names_build(controller_id, listen_names)) ||
        ac_pki_san_add(certificate, names) != 0 ||
        X509_sign(certificate, ca_key, NULL) <= 0) {
        X509_free(certificate);
        certificate = NULL;
    }
    GENERAL_NAMES_free(names);
    OPENSSL_cleanse(common_name, sizeof(common_name));
    return certificate;
}

static int ac_pki_x509_der(X509 *certificate, unsigned char **out,
                           size_t *out_len)
{
    unsigned char *data = NULL;
    unsigned char *cursor;
    int length;

    if (!certificate || !out || !out_len ||
        (length = i2d_X509(certificate, NULL)) <= 0 ||
        length > AC_PKI_MAX_CERT_DER ||
        !(data = OPENSSL_malloc((size_t)length)))
        return -1;
    cursor = data;
    if (i2d_X509(certificate, &cursor) != length) {
        OPENSSL_free(data);
        return -1;
    }
    *out = data;
    *out_len = (size_t)length;
    return 0;
}

static X509 *ac_pki_x509_parse(const unsigned char *data, size_t len)
{
    const unsigned char *cursor = data;
    X509 *certificate;

    if (!data || len == 0 || len > AC_PKI_MAX_CERT_DER || len > LONG_MAX)
        return NULL;
    certificate = d2i_X509(NULL, &cursor, (long)len);
    if (!certificate || cursor != data + len) {
        X509_free(certificate);
        return NULL;
    }
    return certificate;
}

static int ac_pki_certificate_fingerprint(
    X509 *certificate, unsigned char digest[AC_PKI_FINGERPRINT_LEN],
    char text[AC_PKI_KEY_ID_LEN + 1])
{
    unsigned char *der = NULL;
    size_t der_len = 0;
    char hex[AC_PKI_FINGERPRINT_LEN * 2 + 1] = {0};
    int rc = -1;

    if (ac_pki_x509_der(certificate, &der, &der_len) != 0 ||
        !SHA256(der, der_len, digest))
        goto done;
    ac_pki_hex(hex, sizeof(hex), digest, AC_PKI_FINGERPRINT_LEN);
    if (snprintf(text, AC_PKI_KEY_ID_LEN + 1, "sha256:%s", hex) <
        AC_PKI_KEY_ID_LEN + 1)
        rc = 0;
done:
    OPENSSL_free(der);
    OPENSSL_cleanse(hex, sizeof(hex));
    return rc;
}

static int ac_pki_key_usage_exact(X509 *certificate, int expected_bit_a,
                                  int expected_bit_b)
{
    ASN1_BIT_STRING *usage;
    int critical = -1;
    int i;
    int valid = 1;

    usage = X509_get_ext_d2i(certificate, NID_key_usage, &critical, NULL);
    if (!usage || critical != 1)
        valid = 0;
    for (i = 0; valid && i <= 8; i++) {
        int expected = i == expected_bit_a || i == expected_bit_b;

        if (!!ASN1_BIT_STRING_get_bit(usage, i) != expected)
            valid = 0;
    }
    ASN1_BIT_STRING_free(usage);
    return valid;
}

static int ac_pki_basic_constraints(X509 *certificate, int expected_ca)
{
    BASIC_CONSTRAINTS *constraints;
    int critical = -1;
    int valid = 0;

    constraints = X509_get_ext_d2i(certificate, NID_basic_constraints,
                                    &critical, NULL);
    if (constraints && critical == 1 && !!constraints->ca == !!expected_ca &&
        (!expected_ca || (constraints->pathlen &&
                          ASN1_INTEGER_get(constraints->pathlen) == 0)))
        valid = 1;
    BASIC_CONSTRAINTS_free(constraints);
    return valid;
}

static int ac_pki_eku_exact(X509 *certificate, int expected_nid)
{
    EXTENDED_KEY_USAGE *usage;
    int critical = -1;
    int valid = 0;

    usage = X509_get_ext_d2i(certificate, NID_ext_key_usage, &critical, NULL);
    if (usage && critical == 0 && sk_ASN1_OBJECT_num(usage) == 1 &&
        OBJ_obj2nid(sk_ASN1_OBJECT_value(usage, 0)) == expected_nid)
        valid = 1;
    EXTENDED_KEY_USAGE_free(usage);
    return valid;
}

static int ac_pki_time_valid(X509 *certificate)
{
    return certificate && X509_cmp_current_time(X509_get0_notBefore(certificate)) < 0 &&
        X509_cmp_current_time(X509_get0_notAfter(certificate)) > 0;
}

/*
 * True when the only thing wrong with a certificate is that it was issued
 * against a clock that was ahead, so notBefore has not arrived yet.
 *
 * This is a real failure mode on this platform, not a hypothetical: sysfixtime
 * seeds the clock from the newest mtime on disk at boot, which can be hours in
 * the future, and the controller signs its server certificate long before NTP
 * corrects the time. The result is a two-year certificate that every AP
 * correctly refuses, and because the validity check also guards the reissue
 * path, the controller could not sign its way out of it either.
 *
 * Distinguished from plain expiry on purpose. An expired certificate means time
 * has genuinely passed and reissuing is routine; a not-yet-valid one means the
 * clock lied when it was signed, and the fix is to sign again now that the
 * clock is believable.
 */
static int ac_pki_not_yet_valid(X509 *certificate)
{
    return certificate &&
        X509_cmp_current_time(X509_get0_notBefore(certificate)) > 0;
}

/*
 * Is the clock trustworthy enough to stamp a multi-year certificate with?
 *
 * There is no local oracle for the correct time, so this asks a narrower and
 * answerable question: is the clock consistent with what this installation
 * already knows. The CA was signed at some point in this machine's real past, so
 * a current time that precedes the CA's own notBefore cannot be right.
 *
 * That catches a clock that came up too early. It does not catch one that came
 * up ahead, which is the case that actually bit us, and no purely local check
 * can: a clock reading eight hours in the future looks exactly like a clock that
 * is right. This is why the reissue path matters as much as this check does. The
 * pair of them is the fix: refuse to sign when the clock is provably wrong, and
 * sign again once a bad stamp becomes visible.
 */
static int ac_pki_clock_plausible(X509 *ca_certificate)
{
    const ASN1_TIME *ca_not_before;

    if (!ca_certificate)
        return 1;
    ca_not_before = X509_get0_notBefore(ca_certificate);
    /* Negative means the CA's start is in the past, which is what it should be. */
    return ca_not_before && X509_cmp_current_time(ca_not_before) < 0;
}

static int ac_pki_uri_matches(const ASN1_IA5STRING *value,
                              const char *expected)
{
    const unsigned char *data;
    int length;

    if (!value || !expected || (length = ASN1_STRING_length(value)) < 0 ||
        (size_t)length != strlen(expected) ||
        !(data = ASN1_STRING_get0_data(value)))
        return 0;
    return CRYPTO_memcmp(data, expected, (size_t)length) == 0;
}

static int ac_pki_server_san_valid(X509 *certificate,
                                   const char *controller_id,
                                   const struct ac_pki_name_list *expected)
{
    GENERAL_NAMES *names;
    unsigned char matched[AC_PKI_MAX_LISTEN_NAMES] = {0};
    char uri[96];
    int critical = -1;
    int uri_count = 0;
    int valid = 0;
    int i;

    if (!certificate || !controller_id || !expected ||
        snprintf(uri, sizeof(uri), "urn:dreamingwrt:ac:%s", controller_id) >=
            (int)sizeof(uri))
        return 0;
    names = X509_get_ext_d2i(certificate, NID_subject_alt_name,
                             &critical, NULL);
    if (!names || critical != 0 ||
        sk_GENERAL_NAME_num(names) != (int)expected->count + 1)
        goto done;
    for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
        GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
        size_t j;
        int found = 0;

        if (name && name->type == GEN_URI &&
            ac_pki_uri_matches(name->d.uniformResourceIdentifier, uri)) {
            uri_count++;
            continue;
        }
        for (j = 0; name && j < expected->count; j++) {
            const struct ac_pki_name *item = &expected->values[j];

            if (matched[j])
                continue;
            if (item->type == AC_PKI_NAME_DNS && name->type == GEN_DNS &&
                ASN1_STRING_length(name->d.dNSName) == (int)strlen(item->text) &&
                !strncasecmp((const char *)ASN1_STRING_get0_data(name->d.dNSName),
                             item->text, strlen(item->text)))
                found = 1;
            else if (item->type == AC_PKI_NAME_IP && name->type == GEN_IPADD &&
                     ASN1_STRING_length(name->d.iPAddress) ==
                         (int)item->address_len &&
                     CRYPTO_memcmp(ASN1_STRING_get0_data(name->d.iPAddress),
                                   item->address, item->address_len) == 0)
                found = 1;
            if (found) {
                matched[j] = 1;
                break;
            }
        }
        if (!found)
            goto done;
    }
    if (uri_count != 1)
        goto done;
    for (i = 0; i < (int)expected->count; i++)
        if (!matched[i])
            goto done;
    valid = 1;
done:
    GENERAL_NAMES_free(names);
    OPENSSL_cleanse(uri, sizeof(uri));
    OPENSSL_cleanse(matched, sizeof(matched));
    return valid;
}

static int ac_pki_ap_san_valid_stack(GENERAL_NAMES *names, const char *ap_id)
{
    GENERAL_NAME *name;
    char expected[96];
    int valid = 0;

    if (!names || !ap_id ||
        snprintf(expected, sizeof(expected), "urn:dreamingwrt:ap:%s", ap_id) >=
            (int)sizeof(expected) || sk_GENERAL_NAME_num(names) != 1)
        goto done;
    name = sk_GENERAL_NAME_value(names, 0);
    if (name && name->type == GEN_URI &&
        ac_pki_uri_matches(name->d.uniformResourceIdentifier, expected))
        valid = 1;
done:
    OPENSSL_cleanse(expected, sizeof(expected));
    return valid;
}

static int ac_pki_ca_valid(X509 *certificate, EVP_PKEY *key)
{
    EVP_PKEY *public_key = NULL;
    int valid = 0;

    public_key = certificate ? X509_get_pubkey(certificate) : NULL;
    if (certificate && key && public_key &&
        EVP_PKEY_base_id(key) == EVP_PKEY_ED25519 &&
        EVP_PKEY_base_id(public_key) == EVP_PKEY_ED25519 &&
        X509_check_private_key(certificate, key) == 1 &&
        X509_NAME_cmp(X509_get_subject_name(certificate),
                      X509_get_issuer_name(certificate)) == 0 &&
        X509_verify(certificate, public_key) == 1 &&
        ac_pki_time_valid(certificate) &&
        ac_pki_basic_constraints(certificate, 1) &&
        ac_pki_key_usage_exact(certificate, 5, 6) &&
        X509_get_ext_by_NID(certificate, NID_ext_key_usage, -1) < 0 &&
        X509_get_ext_by_NID(certificate, NID_subject_alt_name, -1) < 0)
        valid = 1;
    EVP_PKEY_free(public_key);
    return valid;
}

/*
 * Everything about a server certificate except its validity window: it belongs
 * to this key, was issued by this CA, and carries the right constraints and
 * usage. Split out so the reissue path can accept a certificate whose only
 * defect is a bad clock at signing time without loosening any of these.
 */
static int ac_pki_server_structure_valid(X509 *certificate, EVP_PKEY *key,
                                         X509 *ca_certificate, EVP_PKEY *ca_key)
{
    EVP_PKEY *ca_public = NULL;
    int valid = 0;

    ca_public = ca_certificate ? X509_get_pubkey(ca_certificate) : NULL;
    if (certificate && key && ca_certificate && ca_key && ca_public &&
        EVP_PKEY_base_id(key) == EVP_PKEY_ED25519 &&
        X509_check_private_key(certificate, key) == 1 &&
        X509_NAME_cmp(X509_get_issuer_name(certificate),
                      X509_get_subject_name(ca_certificate)) == 0 &&
        X509_verify(certificate, ca_public) == 1 &&
        ac_pki_basic_constraints(certificate, 0) &&
        ac_pki_key_usage_exact(certificate, 0, -1) &&
        ac_pki_eku_exact(certificate, NID_server_auth))
        valid = 1;
    EVP_PKEY_free(ca_public);
    return valid;
}

static int ac_pki_server_without_san_valid(X509 *certificate, EVP_PKEY *key,
                                           X509 *ca_certificate, EVP_PKEY *ca_key)
{
    return ac_pki_server_structure_valid(certificate, key,
                                         ca_certificate, ca_key) &&
        ac_pki_time_valid(certificate);
}

static int ac_pki_server_valid(X509 *certificate, EVP_PKEY *key,
                               X509 *ca_certificate, EVP_PKEY *ca_key,
                               const char *controller_id,
                               const struct ac_pki_name_list *listen_names)
{
    return ac_pki_server_without_san_valid(certificate, key,
                                           ca_certificate, ca_key) &&
        ac_pki_server_san_valid(certificate, controller_id, listen_names);
}

static int ac_pki_key_store(int dirfd, const char *name, EVP_PKEY *key)
{
    unsigned char raw[AC_PKI_ED25519_KEY_LEN] = {0};
    int rc;

    if (ac_pki_key_raw_private(key, raw) != 0)
        return -1;
    rc = ac_pki_atomic_write(dirfd, name, raw, sizeof(raw));
    OPENSSL_cleanse(raw, sizeof(raw));
    return rc;
}

static EVP_PKEY *ac_pki_key_load(int dirfd, const char *name, int *missing)
{
    unsigned char *raw = NULL;
    size_t raw_len = 0;
    EVP_PKEY *key = NULL;
    int rc;

    if (missing)
        *missing = 0;
    rc = ac_pki_read_file(dirfd, name, AC_PKI_ED25519_KEY_LEN, -1,
                          &raw, &raw_len);
    if (rc == 1) {
        if (missing)
            *missing = 1;
        return NULL;
    }
    if (rc == 0)
        key = ac_pki_key_from_raw(raw, raw_len);
    if (raw) {
        OPENSSL_cleanse(raw, raw_len);
        OPENSSL_free(raw);
    }
    return key;
}

static int ac_pki_certificate_store(int dirfd, const char *name,
                                    X509 *certificate)
{
    unsigned char *der = NULL;
    size_t der_len = 0;
    int rc = -1;

    if (ac_pki_x509_der(certificate, &der, &der_len) == 0)
        rc = ac_pki_atomic_write(dirfd, name, der, der_len);
    OPENSSL_free(der);
    return rc;
}

static int ac_pki_certificate_replace(int dirfd, const char *name,
                                      X509 *certificate)
{
    unsigned char *der = NULL;
    size_t der_len = 0;
    int rc = -1;

    if (ac_pki_x509_der(certificate, &der, &der_len) == 0)
        rc = ac_pki_atomic_replace(dirfd, name, der, der_len);
    OPENSSL_free(der);
    return rc;
}

static X509 *ac_pki_certificate_load(int dirfd, const char *name, int *missing)
{
    unsigned char *der = NULL;
    size_t der_len = 0;
    X509 *certificate = NULL;
    int rc;

    if (missing)
        *missing = 0;
    rc = ac_pki_read_file(dirfd, name, -1, AC_PKI_MAX_CERT_DER,
                          &der, &der_len);
    if (rc == 1) {
        if (missing)
            *missing = 1;
        return NULL;
    }
    if (rc == 0)
        certificate = ac_pki_x509_parse(der, der_len);
    OPENSSL_free(der);
    return certificate;
}

static int ac_pki_test_interrupt(const char *stage)
{
#ifdef AC_PKI_TEST_STANDALONE
    const char *requested = getenv("AC_PKI_TEST_INTERRUPT_AFTER");

    return requested && !strcmp(requested, stage);
#else
    (void)stage;
    return 0;
#endif
}

static int ac_pki_material_initialize(struct ac_pki *pki, int dirfd,
                                      const struct ac_pki_name_list *names)
{
    unsigned char ca_public_digest[AC_PKI_FINGERPRINT_LEN] = {0};
    int ca_key_missing = 0;
    int ca_cert_missing = 0;
    int server_key_missing = 0;
    int server_cert_missing = 0;

    pki->ca_key = ac_pki_key_load(dirfd, AC_PKI_CA_KEY_FILE,
                                  &ca_key_missing);
    if (!pki->ca_key) {
        if (!ca_key_missing ||
            ac_pki_file_status(dirfd, AC_PKI_CA_CERT_FILE,
                               -1, AC_PKI_MAX_CERT_DER) != 0 ||
            !(pki->ca_key = ac_pki_key_generate()) ||
            ac_pki_key_store(dirfd, AC_PKI_CA_KEY_FILE, pki->ca_key) != 0)
            return -1;
        if (ac_pki_test_interrupt("ca-key"))
            return -1;
    }
    if (ac_pki_key_id(pki->ca_key, pki->ca_key_id,
                      ca_public_digest) != 0)
        return -1;
    ac_pki_controller_id_from_digest(ca_public_digest, pki->controller_id);
    pki->ca_cert = ac_pki_certificate_load(dirfd, AC_PKI_CA_CERT_FILE,
                                            &ca_cert_missing);
    if (!pki->ca_cert) {
        if (!ca_cert_missing ||
            !(pki->ca_cert = ac_pki_ca_create(pki->ca_key,
                                               pki->controller_id)) ||
            ac_pki_certificate_store(dirfd, AC_PKI_CA_CERT_FILE,
                                     pki->ca_cert) != 0)
            return -1;
        if (ac_pki_test_interrupt("ca-cert"))
            return -1;
    }
    if (!ac_pki_ca_valid(pki->ca_cert, pki->ca_key) ||
        ac_pki_certificate_fingerprint(pki->ca_cert,
                                       pki->ca_fingerprint,
                                       pki->ca_fingerprint_text) != 0)
        return -1;
    /*
     * With a trustworthy CA in hand, use it as a floor on the clock before
     * signing anything. A current time earlier than the CA's own start cannot be
     * right, and stamping a multi-year certificate from it would bake the error
     * in. Refusing here is better than issuing a certificate that has to be
     * repaired later; the not-yet-valid case below covers the direction this
     * cannot detect.
     */
    if (!ac_pki_clock_plausible(pki->ca_cert)) {
        fprintf(stderr, "[dreamingwrt-ac] refusing to sign: clock reads before "
                        "the CA's own notBefore, time is not yet trustworthy\n");
        return -1;
    }
    pki->server_key = ac_pki_key_load(dirfd, AC_PKI_SERVER_KEY_FILE,
                                      &server_key_missing);
    if (!pki->server_key) {
        if (!server_key_missing ||
            ac_pki_file_status(dirfd, AC_PKI_SERVER_CERT_FILE,
                               -1, AC_PKI_MAX_CERT_DER) != 0 ||
            !(pki->server_key = ac_pki_key_generate()) ||
            ac_pki_key_store(dirfd, AC_PKI_SERVER_KEY_FILE,
                             pki->server_key) != 0)
            return -1;
        if (ac_pki_test_interrupt("server-key"))
            return -1;
    }
    pki->server_cert = ac_pki_certificate_load(dirfd,
                                                AC_PKI_SERVER_CERT_FILE,
                                                &server_cert_missing);
    if (!pki->server_cert) {
        if (!server_cert_missing ||
            !(pki->server_cert = ac_pki_server_create(
                  pki->server_key, pki->ca_cert, pki->ca_key,
                  pki->controller_id, names)) ||
            ac_pki_certificate_store(dirfd, AC_PKI_SERVER_CERT_FILE,
                                     pki->server_cert) != 0)
            return -1;
        if (ac_pki_test_interrupt("server-cert"))
            return -1;
    }
    if (!ac_pki_server_valid(pki->server_cert, pki->server_key,
                             pki->ca_cert, pki->ca_key,
                             pki->controller_id, names)) {
        /*
         * A certificate signed against a clock that was ahead is reissued rather
         * than treated as fatal. The check below would otherwise reject it for
         * the very reason it needs replacing, since the structural validator
         * includes the validity window, and the controller would stay stuck
         * serving a certificate no client will accept.
         *
         * Everything except the dates still has to hold: same key, issued by
         * this CA, correct constraints and usage. Only the time window is
         * forgiven, and only in the not-yet-valid direction.
         */
        if (!ac_pki_server_without_san_valid(pki->server_cert,
                                             pki->server_key,
                                             pki->ca_cert, pki->ca_key) &&
            !(ac_pki_not_yet_valid(pki->server_cert) &&
              ac_pki_server_structure_valid(pki->server_cert,
                                            pki->server_key,
                                            pki->ca_cert, pki->ca_key)))
            return -1;
        if (ac_pki_not_yet_valid(pki->server_cert))
            fprintf(stderr, "[dreamingwrt-ac] server certificate notBefore is in "
                            "the future, reissuing against the current clock\n");
        X509_free(pki->server_cert);
        pki->server_cert = ac_pki_server_create(
            pki->server_key, pki->ca_cert, pki->ca_key,
            pki->controller_id, names);
        if (!pki->server_cert ||
            ac_pki_certificate_replace(dirfd, AC_PKI_SERVER_CERT_FILE,
                                       pki->server_cert) != 0 ||
            !ac_pki_server_valid(pki->server_cert, pki->server_key,
                                 pki->ca_cert, pki->ca_key,
                                 pki->controller_id, names))
            return -1;
    }
    OPENSSL_cleanse(ca_public_digest, sizeof(ca_public_digest));
    return 0;
}

int ac_pki_init(struct ac_pki **out)
{
    const char *configured = getenv("DREAMINGWRT_AC_PKI_DIR");
    const char *directory = configured && configured[0] ?
        configured : AC_PKI_DEFAULT_DIR;
    struct ac_pki_name_list names;
    struct ac_pki *pki = NULL;
    int dirfd = -1;
    int lockfd = -1;
    int rc = -1;

    if (!out || strlen(directory) >= sizeof(pki->directory) ||
        ac_pki_listen_names(&names) != 0)
        return -1;
    *out = NULL;
    dirfd = ac_pki_prepare_directory(directory);
    if (dirfd < 0 || (lockfd = ac_pki_lock(dirfd)) < 0 ||
        !(pki = calloc(1, sizeof(*pki))))
        goto done;
    snprintf(pki->directory, sizeof(pki->directory), "%s", directory);
    if (ac_pki_material_initialize(pki, dirfd, &names) != 0)
        goto done;
    *out = pki;
    pki = NULL;
    rc = 0;
done:
    if (pki) {
        X509_free(pki->server_cert);
        EVP_PKEY_free(pki->server_key);
        X509_free(pki->ca_cert);
        EVP_PKEY_free(pki->ca_key);
        OPENSSL_cleanse(pki, sizeof(*pki));
        free(pki);
    }
    ac_pki_unlock(lockfd);
    if (dirfd >= 0)
        close(dirfd);
    OPENSSL_cleanse(&names, sizeof(names));
    return rc;
}

void ac_pki_free(struct ac_pki *pki)
{
    if (!pki)
        return;
    X509_free(pki->server_cert);
    EVP_PKEY_free(pki->server_key);
    X509_free(pki->ca_cert);
    EVP_PKEY_free(pki->ca_key);
    OPENSSL_cleanse(pki, sizeof(*pki));
    free(pki);
}

const char *ac_pki_controller_id(const struct ac_pki *pki)
{
    return pki ? pki->controller_id : NULL;
}

const char *ac_pki_ca_key_id(const struct ac_pki *pki)
{
    return pki ? pki->ca_key_id : NULL;
}

const unsigned char *ac_pki_ca_fingerprint_sha256(const struct ac_pki *pki)
{
    return pki ? pki->ca_fingerprint : NULL;
}

const char *ac_pki_ca_fingerprint_text(const struct ac_pki *pki)
{
    return pki ? pki->ca_fingerprint_text : NULL;
}

X509 *ac_pki_ca_certificate_dup(const struct ac_pki *pki)
{
    if (!pki || !pki->ca_cert || X509_up_ref(pki->ca_cert) != 1)
        return NULL;
    return pki->ca_cert;
}

X509 *ac_pki_server_certificate_dup(const struct ac_pki *pki)
{
    if (!pki || !pki->server_cert || X509_up_ref(pki->server_cert) != 1)
        return NULL;
    return pki->server_cert;
}

EVP_PKEY *ac_pki_server_private_key_dup(const struct ac_pki *pki)
{
    if (!pki || !pki->server_key || EVP_PKEY_up_ref(pki->server_key) != 1)
        return NULL;
    return pki->server_key;
}

int ac_pki_ca_der(const struct ac_pki *pki, unsigned char **out,
                  size_t *out_len)
{
    return pki ? ac_pki_x509_der(pki->ca_cert, out, out_len) : -1;
}

int ac_pki_ca_pem(const struct ac_pki *pki, unsigned char **out,
                  size_t *out_len)
{
    BIO *bio = NULL;
    BUF_MEM *memory = NULL;
    unsigned char *data = NULL;
    int rc = -1;

    if (!pki || !out || !out_len || !(bio = BIO_new(BIO_s_mem())) ||
        PEM_write_bio_X509(bio, pki->ca_cert) != 1)
        goto done;
    BIO_get_mem_ptr(bio, &memory);
    if (!memory || !memory->data || !memory->length ||
        !(data = OPENSSL_malloc(memory->length)))
        goto done;
    memcpy(data, memory->data, memory->length);
    *out = data;
    *out_len = memory->length;
    data = NULL;
    rc = 0;
done:
    OPENSSL_free(data);
    BIO_free(bio);
    return rc;
}

static int ac_pki_csr_verify(const char *ap_id,
                             const unsigned char raw_public_key[32],
                             const unsigned char *csr_der, size_t csr_der_len,
                             X509_REQ **request_out, EVP_PKEY **key_out)
{
    const unsigned char *cursor = csr_der;
    X509_REQ *request = NULL;
    EVP_PKEY *key = NULL;
    STACK_OF(X509_EXTENSION) *extensions = NULL;
    GENERAL_NAMES *names = NULL;
    unsigned char actual_public[AC_PKI_ED25519_KEY_LEN] = {0};
    size_t actual_public_len = sizeof(actual_public);
    int valid = 0;

    if (!ap_id || !raw_public_key || !csr_der || !csr_der_len ||
        csr_der_len > AC_PKI_MAX_CSR_DER || csr_der_len > LONG_MAX ||
        !(request = d2i_X509_REQ(NULL, &cursor, (long)csr_der_len)) ||
        cursor != csr_der + csr_der_len || !(key = X509_REQ_get_pubkey(request)) ||
        EVP_PKEY_base_id(key) != EVP_PKEY_ED25519 ||
        X509_REQ_verify(request, key) != 1 ||
        EVP_PKEY_get_raw_public_key(key, actual_public,
                                    &actual_public_len) != 1 ||
        actual_public_len != sizeof(actual_public) ||
        CRYPTO_memcmp(actual_public, raw_public_key,
                      sizeof(actual_public)) != 0 ||
        !(extensions = X509_REQ_get_extensions(request)) ||
        sk_X509_EXTENSION_num(extensions) != 1 ||
        OBJ_obj2nid(X509_EXTENSION_get_object(
            sk_X509_EXTENSION_value(extensions, 0))) != NID_subject_alt_name ||
        !(names = X509V3_EXT_d2i(sk_X509_EXTENSION_value(extensions, 0))) ||
        !ac_pki_ap_san_valid_stack(names, ap_id))
        goto done;
    *request_out = request;
    *key_out = key;
    request = NULL;
    key = NULL;
    valid = 1;
done:
    GENERAL_NAMES_free(names);
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
    X509_REQ_free(request);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(actual_public, sizeof(actual_public));
    return valid ? 0 : -1;
}

static int ac_pki_uuid_valid(const char *value)
{
    static const size_t hyphens[] = {8, 13, 18, 23};
    size_t i;
    size_t h = 0;

    if (!value || strlen(value) != AC_PKI_CONTROLLER_ID_LEN ||
        value[14] != '4' ||
        (value[19] != '8' && value[19] != '9' &&
         value[19] != 'a' && value[19] != 'b'))
        return 0;
    for (i = 0; i < AC_PKI_CONTROLLER_ID_LEN; i++) {
        if (h < sizeof(hyphens) / sizeof(hyphens[0]) && i == hyphens[h]) {
            if (value[i] != '-')
                return 0;
            h++;
        } else if (!((value[i] >= '0' && value[i] <= '9') ||
                     (value[i] >= 'a' && value[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int ac_pki_serial_text(X509 *certificate, char *out, size_t out_size)
{
    BIGNUM *number = NULL;
    char *hex = NULL;
    size_t i;
    int rc = -1;

    number = ASN1_INTEGER_to_BN(X509_get_serialNumber(certificate), NULL);
    hex = number ? BN_bn2hex(number) : NULL;
    if (!hex || strlen(hex) + 1 > out_size)
        goto done;
    for (i = 0; hex[i]; i++)
        out[i] = hex[i] >= 'A' && hex[i] <= 'F' ?
            (char)(hex[i] - 'A' + 'a') : hex[i];
    out[i] = '\0';
    rc = 0;
done:
    OPENSSL_free(hex);
    BN_free(number);
    return rc;
}

int ac_pki_issue_ap_certificate(
    const struct ac_pki *pki, const char *ap_id,
    const unsigned char raw_public_key[32],
    const unsigned char *csr_der, size_t csr_der_len,
    struct ac_pki_issued_certificate **out)
{
    struct ac_pki_issued_certificate *issued = NULL;
    X509_REQ *request = NULL;
    EVP_PKEY *request_key = NULL;
    X509 *certificate = NULL;
    X509_NAME *subject;
    GENERAL_NAMES *names = NULL;
    char common_name[96];
    int rc = -1;

    if (!pki || !out || !ac_pki_uuid_valid(ap_id) ||
        ac_pki_csr_verify(ap_id, raw_public_key, csr_der, csr_der_len,
                          &request, &request_key) != 0 ||
        snprintf(common_name, sizeof(common_name), "DreamingWrt AP %s", ap_id) >=
            (int)sizeof(common_name) || !(certificate = X509_new()) ||
        X509_set_version(certificate, 2) != 1 ||
        ac_pki_serial_set(certificate) != 0 ||
        !(issued = calloc(1, sizeof(*issued))) ||
        ac_pki_validity_set(certificate, AC_PKI_CLIENT_LIFETIME,
                            &issued->not_before, &issued->not_after) != 0 ||
        X509_set_pubkey(certificate, request_key) != 1 ||
        !(subject = X509_get_subject_name(certificate)) ||
        ac_pki_name_set(subject, common_name) != 0 ||
        X509_set_issuer_name(certificate,
                             X509_get_subject_name(pki->ca_cert)) != 1 ||
        ac_pki_extension_conf(certificate, pki->ca_cert,
                              NID_basic_constraints,
                              "critical,CA:FALSE") != 0 ||
        ac_pki_extension_conf(certificate, pki->ca_cert, NID_key_usage,
                              "critical,digitalSignature") != 0 ||
        ac_pki_extension_conf(certificate, pki->ca_cert,
                              NID_ext_key_usage, "clientAuth") != 0 ||
        ac_pki_extension_conf(certificate, pki->ca_cert,
                              NID_subject_key_identifier, "hash") != 0 ||
        ac_pki_extension_conf(certificate, pki->ca_cert,
                              NID_authority_key_identifier,
                              "keyid:always") != 0 ||
        !(names = ac_pki_ap_name_build(ap_id)) ||
        ac_pki_san_add(certificate, names) != 0 ||
        X509_sign(certificate, pki->ca_key, NULL) <= 0 ||
        ac_pki_basic_constraints(certificate, 0) == 0 ||
        !ac_pki_key_usage_exact(certificate, 0, -1) ||
        !ac_pki_eku_exact(certificate, NID_client_auth) ||
        !ac_pki_ap_san_valid_stack(names, ap_id) ||
        ac_pki_x509_der(certificate, &issued->der, &issued->der_len) != 0 ||
        ac_pki_serial_text(certificate, issued->serial,
                           sizeof(issued->serial)) != 0 ||
        ac_pki_certificate_fingerprint(certificate, issued->fingerprint,
                                       issued->fingerprint_text) != 0)
        goto done;
    snprintf(issued->issuer_key_id, sizeof(issued->issuer_key_id), "%s",
             pki->ca_key_id);
    issued->certificate = certificate;
    certificate = NULL;
    *out = issued;
    issued = NULL;
    rc = 0;
done:
    if (issued) {
        X509_free(issued->certificate);
        OPENSSL_free(issued->der);
        OPENSSL_cleanse(issued, sizeof(*issued));
        free(issued);
    }
    GENERAL_NAMES_free(names);
    X509_free(certificate);
    EVP_PKEY_free(request_key);
    X509_REQ_free(request);
    OPENSSL_cleanse(common_name, sizeof(common_name));
    return rc;
}

void ac_pki_issued_certificate_free(
    struct ac_pki_issued_certificate *certificate)
{
    if (!certificate)
        return;
    X509_free(certificate->certificate);
    OPENSSL_free(certificate->der);
    OPENSSL_cleanse(certificate, sizeof(*certificate));
    free(certificate);
}

const unsigned char *ac_pki_issued_certificate_der(
    const struct ac_pki_issued_certificate *certificate, size_t *out_len)
{
    if (!certificate || !out_len)
        return NULL;
    *out_len = certificate->der_len;
    return certificate->der;
}

X509 *ac_pki_issued_certificate_x509_dup(
    const struct ac_pki_issued_certificate *certificate)
{
    if (!certificate || !certificate->certificate ||
        X509_up_ref(certificate->certificate) != 1)
        return NULL;
    return certificate->certificate;
}

const char *ac_pki_issued_certificate_serial(
    const struct ac_pki_issued_certificate *certificate)
{
    return certificate ? certificate->serial : NULL;
}

const char *ac_pki_issued_certificate_issuer_key_id(
    const struct ac_pki_issued_certificate *certificate)
{
    return certificate ? certificate->issuer_key_id : NULL;
}

const unsigned char *ac_pki_issued_certificate_fingerprint_sha256(
    const struct ac_pki_issued_certificate *certificate)
{
    return certificate ? certificate->fingerprint : NULL;
}

const char *ac_pki_issued_certificate_fingerprint_text(
    const struct ac_pki_issued_certificate *certificate)
{
    return certificate ? certificate->fingerprint_text : NULL;
}

int64_t ac_pki_issued_certificate_not_before(
    const struct ac_pki_issued_certificate *certificate)
{
    return certificate ? certificate->not_before : 0;
}

int64_t ac_pki_issued_certificate_not_after(
    const struct ac_pki_issued_certificate *certificate)
{
    return certificate ? certificate->not_after : 0;
}
