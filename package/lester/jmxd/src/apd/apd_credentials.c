// SPDX-License-Identifier: GPL-2.0-or-later
#ifdef APD_CREDENTIALS_TEST_STANDALONE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#define APD_AP_ID_LEN 36
#define APD_ED25519_KEY_LEN 32
struct apd_node_identity {
    char ap_id[APD_AP_ID_LEN + 1];
    char key_id[72];
    unsigned char public_key[APD_ED25519_KEY_LEN];
    int64_t created_at;
};
int apd_db_identity_get(struct apd_node_identity *out);
EVP_PKEY *apd_identity_key_open(void);
#else
#include "apd_internal.h"
#include <arpa/inet.h>
#include <limits.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

#define APD_CREDENTIALS_PKI_DIR "/etc/dreamingwrt/apd-pki"
#define APD_CREDENTIALS_BOOTSTRAP_FILE "bootstrap.json"
#define APD_CREDENTIALS_CA_FILE "controller-ca.pem"
#define APD_CREDENTIALS_CERT_FILE "client-cert.der"
#define APD_CREDENTIALS_METADATA_FILE "enrollment.json"
#define APD_CREDENTIALS_LOCK_FILE ".credentials.lock"
#define APD_CREDENTIALS_JSON_MAX 16384
#define APD_CREDENTIALS_CERT_MAX 65536
#define APD_CREDENTIALS_UUID_LEN 36
#define APD_CREDENTIALS_TOKEN_LEN 43
#define APD_CREDENTIALS_SITE_MAX 64
#define APD_CREDENTIALS_HOST_MAX 253
#define APD_CREDENTIALS_DIGEST_LEN 71
#define APD_CREDENTIALS_SERIAL_MAX 256
#define APD_CREDENTIALS_STATE_PENDING "mtls_pending"
#define APD_CREDENTIALS_STATE_ADOPTED "adopted"

/* client-cert.der is canonical DER. enrollment.json is the non-secret sidecar. */
#ifdef APD_CREDENTIALS_TEST_STANDALONE
struct apd_bootstrap_config {
    int version;
    char controller_host[APD_CREDENTIALS_HOST_MAX + 1];
    uint16_t controller_port;
    int controller_id_present;
    char controller_id[APD_CREDENTIALS_UUID_LEN + 1];
    char token_id[APD_CREDENTIALS_UUID_LEN + 1];
    char token[APD_CREDENTIALS_TOKEN_LEN + 1];
    char site_id[APD_CREDENTIALS_SITE_MAX + 1];
    char hardware_digest[APD_CREDENTIALS_DIGEST_LEN + 1];
    char ca_cert_pem_path[PATH_MAX];
};

struct apd_credentials_certificate_input {
    const unsigned char *certificate_der;
    size_t certificate_der_len;
    char controller_id[APD_CREDENTIALS_UUID_LEN + 1];
    char enrollment_id[APD_CREDENTIALS_UUID_LEN + 1];
    char certificate_id[APD_CREDENTIALS_UUID_LEN + 1];
};

struct apd_enrollment_metadata {
    int version;
    char controller_id[APD_CREDENTIALS_UUID_LEN + 1];
    char controller_host[APD_CREDENTIALS_HOST_MAX + 1];
    uint16_t controller_port;
    char enrollment_id[APD_CREDENTIALS_UUID_LEN + 1];
    char certificate_id[APD_CREDENTIALS_UUID_LEN + 1];
    char ap_id[APD_AP_ID_LEN + 1];
    char serial[APD_CREDENTIALS_SERIAL_MAX + 1];
    int64_t not_before;
    int64_t not_after;
    char certificate_fingerprint[APD_CREDENTIALS_DIGEST_LEN + 1];
    char ca_fingerprint[APD_CREDENTIALS_DIGEST_LEN + 1];
    char ca_cert_pem_path[PATH_MAX];
    char state[16];
};

enum apd_credentials_activate_result {
    APD_CREDENTIALS_ACTIVATE_OK = 0,
    APD_CREDENTIALS_ACTIVATE_CONTROLLER_INVALID = -1,
    APD_CREDENTIALS_ACTIVATE_ENROLLMENT_INVALID = -2,
    APD_CREDENTIALS_ACTIVATE_CERTIFICATE_INVALID = -3,
    APD_CREDENTIALS_ACTIVATE_FINGERPRINT_MISSING = -4,
    APD_CREDENTIALS_ACTIVATE_LOCK_FAILED = -5,
    APD_CREDENTIALS_ACTIVATE_VALIDATE_FAILED = -6,
    APD_CREDENTIALS_ACTIVATE_BINDING_MISMATCH = -7,
    APD_CREDENTIALS_ACTIVATE_BOOTSTRAP_REMOVE_FAILED = -8,
    APD_CREDENTIALS_ACTIVATE_METADATA_COMMIT_FAILED = -9,
};

struct apd_credentials_unpair_report {
    int certificate_removed;
    int enrollment_removed;
    int bootstrap_removed;
};

enum apd_credentials_unpair_result {
    APD_CREDENTIALS_UNPAIR_OK = 0,
    APD_CREDENTIALS_UNPAIR_LOCK_FAILED = -1,
    APD_CREDENTIALS_UNPAIR_CERTIFICATE_FAILED = -2,
    APD_CREDENTIALS_UNPAIR_METADATA_FAILED = -3,
    APD_CREDENTIALS_UNPAIR_BOOTSTRAP_FAILED = -4,
};
int apd_credentials_unpair(struct apd_credentials_unpair_report *out);
#endif

enum apd_json_value_type {
    APD_JSON_STRING,
    APD_JSON_INTEGER
};

struct apd_json_member {
    char key[64];
    enum apd_json_value_type type;
    char string[PATH_MAX];
    int64_t integer;
};

struct apd_json_object {
    struct apd_json_member members[20];
    size_t count;
};

struct apd_credentials_lock {
    int fd;
    char directory[PATH_MAX];
};

static X509 *apd_credentials_ca_open(
    const char *path, unsigned char **der, size_t *der_len,
    char fingerprint[APD_CREDENTIALS_DIGEST_LEN + 1]);

static void apd_credentials_copy(char *destination, size_t destination_size,
                                 const char *source)
{
    size_t length = source ? strlen(source) : 0;

    if (!destination || destination_size == 0)
        return;
    if (length >= destination_size)
        length = destination_size - 1;
    if (length > 0)
        memcpy(destination, source, length);
    destination[length] = '\0';
}

static int apd_credentials_path(char *out, size_t out_size,
                                const char *directory, const char *name)
{
    int length;

    if (!out || !directory || !name || directory[0] != '/')
        return -1;
    length = snprintf(out, out_size, "%s/%s", directory, name);
    return length > 0 && (size_t)length < out_size ? 0 : -1;
}

const char *apd_credentials_pki_dir(void)
{
    const char *configured = getenv("DREAMINGWRT_APD_PKI_DIR");

    return configured && configured[0] ? configured : APD_CREDENTIALS_PKI_DIR;
}

void apd_credentials_bootstrap_cleanse(struct apd_bootstrap_config *config)
{
    if (config)
        OPENSSL_cleanse(config, sizeof(*config));
}

void apd_credentials_metadata_cleanse(struct apd_enrollment_metadata *metadata)
{
    if (metadata)
        OPENSSL_cleanse(metadata, sizeof(*metadata));
}

static int apd_credentials_directory_validate(const char *path, int create)
{
    struct stat status;

    if (!path || path[0] != '/' || strlen(path) >= PATH_MAX)
        return -1;
    if (lstat(path, &status) != 0) {
        if (!create || errno != ENOENT || mkdir(path, 0700) != 0)
            return -1;
        if (lstat(path, &status) != 0)
            return -1;
    }
    if (!S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode) ||
        status.st_uid != geteuid() || (status.st_mode & 0777) != 0700)
        return -1;
    return 0;
}

static int apd_credentials_file_status(int fd, mode_t mode,
                                       size_t maximum, struct stat *out)
{
    struct stat status;

    if (fd < 0 || fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_uid != geteuid() || status.st_nlink != 1 ||
        (status.st_mode & 0777) != mode || status.st_size < 0 ||
        (uint64_t)status.st_size > maximum)
        return -1;
    if (out)
        *out = status;
    return 0;
}

static int apd_credentials_read_secure(const char *path, size_t maximum,
                                       unsigned char **out, size_t *out_len)
{
    struct stat status;
    unsigned char *buffer = NULL;
    size_t offset = 0;
    ssize_t count;
    int fd = -1;
    int rc = -1;

    if (!path || !out || !out_len)
        return -1;
    *out = NULL;
    *out_len = 0;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || apd_credentials_file_status(fd, 0600, maximum, &status) != 0 ||
        status.st_size == 0)
        goto done;
    buffer = calloc(1, (size_t)status.st_size + 1);
    if (!buffer)
        goto done;
    while (offset < (size_t)status.st_size) {
        count = read(fd, buffer + offset, (size_t)status.st_size - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            goto done;
        offset += (size_t)count;
    }
    if (memchr(buffer, '\0', offset) != NULL)
        goto done;
    *out = buffer;
    *out_len = offset;
    buffer = NULL;
    rc = 0;
done:
    if (fd >= 0)
        close(fd);
    if (buffer) {
        OPENSSL_cleanse(buffer, (size_t)(status.st_size > 0 ? status.st_size : 0));
        free(buffer);
    }
    return rc;
}

static int apd_credentials_read_binary_secure(const char *path, size_t maximum,
                                              unsigned char **out,
                                              size_t *out_len)
{
    struct stat status;
    unsigned char *buffer = NULL;
    size_t offset = 0;
    ssize_t count;
    int fd = -1;
    int rc = -1;

    if (!path || !out || !out_len)
        return -1;
    *out = NULL;
    *out_len = 0;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || apd_credentials_file_status(fd, 0600, maximum, &status) != 0 ||
        status.st_size == 0)
        goto done;
    buffer = malloc((size_t)status.st_size);
    if (!buffer)
        goto done;
    while (offset < (size_t)status.st_size) {
        count = read(fd, buffer + offset, (size_t)status.st_size - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            goto done;
        offset += (size_t)count;
    }
    *out = buffer;
    *out_len = offset;
    buffer = NULL;
    rc = 0;
done:
    if (fd >= 0)
        close(fd);
    if (buffer) {
        OPENSSL_cleanse(buffer, (size_t)(status.st_size > 0 ? status.st_size : 0));
        free(buffer);
    }
    return rc;
}

static void apd_json_space(const unsigned char *data, size_t length,
                           size_t *offset)
{
    while (*offset < length &&
           (data[*offset] == ' ' || data[*offset] == '\t' ||
            data[*offset] == '\r' || data[*offset] == '\n'))
        (*offset)++;
}

static int apd_json_hex(unsigned char character)
{
    if (character >= '0' && character <= '9')
        return character - '0';
    if (character >= 'a' && character <= 'f')
        return character - 'a' + 10;
    if (character >= 'A' && character <= 'F')
        return character - 'A' + 10;
    return -1;
}

static int apd_json_string(const unsigned char *data, size_t length,
                           size_t *offset, char *out, size_t out_size)
{
    size_t written = 0;

    if (*offset >= length || data[(*offset)++] != '"' || out_size == 0)
        return -1;
    while (*offset < length) {
        unsigned char character = data[(*offset)++];
        int value;

        if (character == '"') {
            out[written] = '\0';
            return 0;
        }
        if (character == '\\') {
            if (*offset >= length)
                return -1;
            character = data[(*offset)++];
            if (character == '"' || character == '\\' || character == '/') {
                /* already decoded */
            } else if (character == 'b') {
                character = '\b';
            } else if (character == 'f') {
                character = '\f';
            } else if (character == 'n') {
                character = '\n';
            } else if (character == 'r') {
                character = '\r';
            } else if (character == 't') {
                character = '\t';
            } else if (character == 'u') {
                size_t i;
                value = 0;
                if (length - *offset < 4)
                    return -1;
                for (i = 0; i < 4; i++) {
                    int digit = apd_json_hex(data[(*offset)++]);
                    if (digit < 0)
                        return -1;
                    value = value * 16 + digit;
                }
                if (value <= 0 || value > 0x7e)
                    return -1;
                character = (unsigned char)value;
            } else {
                return -1;
            }
        }
        if (character < 0x20 || character > 0x7e || written + 1 >= out_size)
            return -1;
        out[written++] = (char)character;
    }
    return -1;
}

static int apd_json_integer(const unsigned char *data, size_t length,
                            size_t *offset, int64_t *out)
{
    uint64_t value = 0;
    int negative = 0;
    size_t start = *offset;

    if (*offset < length && data[*offset] == '-') {
        negative = 1;
        (*offset)++;
    }
    if (*offset >= length || data[*offset] < '0' || data[*offset] > '9' ||
        (data[*offset] == '0' && *offset + 1 < length &&
         data[*offset + 1] >= '0' && data[*offset + 1] <= '9'))
        return -1;
    while (*offset < length && data[*offset] >= '0' && data[*offset] <= '9') {
        unsigned int digit = data[(*offset)++] - '0';
        if (value > (UINT64_MAX - digit) / 10)
            return -1;
        value = value * 10 + digit;
    }
    if (*offset == start || value > (uint64_t)INT64_MAX + (negative ? 1U : 0U))
        return -1;
    if (negative && value == (uint64_t)INT64_MAX + 1U)
        *out = INT64_MIN;
    else
        *out = negative ? -(int64_t)value : (int64_t)value;
    return 0;
}

static int apd_json_parse(const unsigned char *data, size_t length,
                          struct apd_json_object *out)
{
    size_t offset = 0;

    if (!data || !out || length == 0 || length > APD_CREDENTIALS_JSON_MAX)
        return -1;
    memset(out, 0, sizeof(*out));
    apd_json_space(data, length, &offset);
    if (offset >= length || data[offset++] != '{')
        return -1;
    apd_json_space(data, length, &offset);
    if (offset < length && data[offset] == '}')
        offset++;
    else {
        for (;;) {
            struct apd_json_member *member;
            size_t i;

            if (out->count >= sizeof(out->members) / sizeof(out->members[0]))
                return -1;
            member = &out->members[out->count];
            if (apd_json_string(data, length, &offset, member->key,
                                sizeof(member->key)) != 0)
                return -1;
            for (i = 0; i < out->count; i++)
                if (strcmp(out->members[i].key, member->key) == 0)
                    return -1;
            apd_json_space(data, length, &offset);
            if (offset >= length || data[offset++] != ':')
                return -1;
            apd_json_space(data, length, &offset);
            if (offset < length && data[offset] == '"') {
                member->type = APD_JSON_STRING;
                if (apd_json_string(data, length, &offset, member->string,
                                    sizeof(member->string)) != 0)
                    return -1;
            } else {
                member->type = APD_JSON_INTEGER;
                if (apd_json_integer(data, length, &offset, &member->integer) != 0)
                    return -1;
            }
            out->count++;
            apd_json_space(data, length, &offset);
            if (offset < length && data[offset] == ',') {
                offset++;
                apd_json_space(data, length, &offset);
                if (offset >= length || data[offset] == '}')
                    return -1;
                continue;
            }
            if (offset >= length || data[offset++] != '}')
                return -1;
            break;
        }
    }
    apd_json_space(data, length, &offset);
    return offset == length ? 0 : -1;
}

static const struct apd_json_member *apd_json_member_get(
    const struct apd_json_object *object, const char *key)
{
    size_t i;

    for (i = 0; object && i < object->count; i++)
        if (strcmp(object->members[i].key, key) == 0)
            return &object->members[i];
    return NULL;
}

static int apd_json_known(const struct apd_json_object *object,
                          const char *const *known, size_t known_count)
{
    size_t i;
    size_t j;

    for (i = 0; i < object->count; i++) {
        for (j = 0; j < known_count; j++)
            if (strcmp(object->members[i].key, known[j]) == 0)
                break;
        if (j == known_count)
            return -1;
    }
    return 0;
}

static int apd_json_get_string(const struct apd_json_object *object,
                               const char *key, char *out, size_t out_size,
                               int required)
{
    const struct apd_json_member *member = apd_json_member_get(object, key);

    if (!member) {
        if (required)
            return -1;
        if (out && out_size)
            out[0] = '\0';
        return 0;
    }
    if (member->type != APD_JSON_STRING || strlen(member->string) >= out_size)
        return -1;
    apd_credentials_copy(out, out_size, member->string);
    return 0;
}

static int apd_json_get_integer(const struct apd_json_object *object,
                                const char *key, int64_t *out)
{
    const struct apd_json_member *member = apd_json_member_get(object, key);

    if (!member || member->type != APD_JSON_INTEGER || !out)
        return -1;
    *out = member->integer;
    return 0;
}

static int apd_credentials_uuid_version(const char *value, char version)
{
    size_t i;

    if (!value || strlen(value) != APD_CREDENTIALS_UUID_LEN ||
        value[14] != version ||
        (value[19] != '8' && value[19] != '9' &&
         value[19] != 'a' && value[19] != 'b'))
        return 0;
    for (i = 0; i < APD_CREDENTIALS_UUID_LEN; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-')
                return 0;
        } else if (!((value[i] >= '0' && value[i] <= '9') ||
                     (value[i] >= 'a' && value[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int apd_credentials_uuid(const char *value)
{
    return apd_credentials_uuid_version(value, '4');
}

static int apd_credentials_controller_id(const char *value)
{
    return apd_credentials_uuid_version(value, '5');
}

static int apd_credentials_digest(const char *value, int allow_empty)
{
    size_t i;

    if (allow_empty && value && value[0] == '\0')
        return 1;
    if (!value || strlen(value) != APD_CREDENTIALS_DIGEST_LEN ||
        memcmp(value, "sha256:", 7) != 0)
        return 0;
    for (i = 7; i < APD_CREDENTIALS_DIGEST_LEN; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return 0;
    return 1;
}

static int apd_credentials_token(const char *value)
{
    size_t i;

    if (!value || strlen(value) != APD_CREDENTIALS_TOKEN_LEN)
        return 0;
    for (i = 0; i < APD_CREDENTIALS_TOKEN_LEN; i++)
        if (!((value[i] >= 'A' && value[i] <= 'Z') ||
              (value[i] >= 'a' && value[i] <= 'z') ||
              (value[i] >= '0' && value[i] <= '9') ||
              value[i] == '-' || value[i] == '_'))
            return 0;
    return 1;
}

static int apd_credentials_dns_name(const char *host)
{
    const char *label = host;
    const char *cursor;
    size_t total;

    if (!host || !(total = strlen(host)) || total > APD_CREDENTIALS_HOST_MAX ||
        host[total - 1] == '.')
        return 0;
    for (cursor = host;; cursor++) {
        unsigned char character = (unsigned char)*cursor;

        if (character == '.' || character == '\0') {
            size_t length = (size_t)(cursor - label);
            if (length == 0 || length > 63 || label[0] == '-' ||
                label[length - 1] == '-')
                return 0;
            if (character == '\0')
                return 1;
            label = cursor + 1;
        } else if (!((character >= 'A' && character <= 'Z') ||
                     (character >= 'a' && character <= 'z') ||
                     (character >= '0' && character <= '9') ||
                     character == '-')) {
            return 0;
        }
    }
}

static int apd_credentials_host(const char *host)
{
    unsigned char address[sizeof(struct in6_addr)];
    const unsigned char *cursor;
    int numeric_dotted = 1;

    if (!host)
        return 0;
    if (inet_pton(AF_INET, host, address) == 1 ||
        inet_pton(AF_INET6, host, address) == 1)
        return 1;
    for (cursor = (const unsigned char *)host; *cursor; cursor++)
        if (!((*cursor >= '0' && *cursor <= '9') || *cursor == '.')) {
            numeric_dotted = 0;
            break;
        }
    return !numeric_dotted && apd_credentials_dns_name(host);
}

static int apd_credentials_printable(const char *value, size_t maximum,
                                     int allow_empty)
{
    size_t length;
    size_t i;

    if (!value || (length = strlen(value)) > maximum || (!allow_empty && !length))
        return 0;
    for (i = 0; i < length; i++)
        if ((unsigned char)value[i] < 0x20 || (unsigned char)value[i] > 0x7e)
            return 0;
    return 1;
}

static int apd_credentials_serial(const char *value)
{
    size_t i;
    size_t length;

    if (!value || !(length = strlen(value)) ||
        length > APD_CREDENTIALS_SERIAL_MAX)
        return 0;
    for (i = 0; i < length; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return 0;
    return 1;
}

static int apd_credentials_path_absent(const char *path)
{
    struct stat status;

    if (lstat(path, &status) == 0)
        return 0;
    return errno == ENOENT;
}

static int apd_credentials_lock_open(struct apd_credentials_lock *lock)
{
    char path[PATH_MAX];
    struct stat status;
    const char *directory = apd_credentials_pki_dir();

    if (!lock || apd_credentials_directory_validate(directory, 1) != 0 ||
        apd_credentials_path(path, sizeof(path), directory,
                             APD_CREDENTIALS_LOCK_FILE) != 0)
        return -1;
    memset(lock, 0, sizeof(*lock));
    lock->fd = -1;
    apd_credentials_copy(lock->directory, sizeof(lock->directory), directory);
    lock->fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock->fd < 0 ||
        apd_credentials_file_status(lock->fd, 0600, 0, &status) != 0 ||
        flock(lock->fd, LOCK_EX) != 0) {
        if (lock->fd >= 0)
            close(lock->fd);
        lock->fd = -1;
        return -1;
    }
    return 0;
}

static void apd_credentials_lock_close(struct apd_credentials_lock *lock)
{
    if (lock && lock->fd >= 0) {
        flock(lock->fd, LOCK_UN);
        close(lock->fd);
        lock->fd = -1;
    }
}

static int apd_credentials_parent_sync(const char *directory)
{
    int fd = open(directory, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    int rc;

    if (fd < 0)
        return -1;
    rc = fsync(fd);
    close(fd);
    return rc == 0 ? 0 : -1;
}

static int apd_credentials_write_all(int fd, const unsigned char *data,
                                     size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t written = write(fd, data + offset, length - offset);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return -1;
        offset += (size_t)written;
    }
    return 0;
}

static int apd_credentials_atomic_write(const char *directory,
                                        const char *name,
                                        const unsigned char *data,
                                        size_t length)
{
    unsigned char random[8];
    char temporary[PATH_MAX] = {0};
    char destination[PATH_MAX];
    struct stat status;
    int fd = -1;
    int attempt;
    int rc = -1;

    if (!directory || !name || !data || !length ||
        apd_credentials_path(destination, sizeof(destination), directory, name) != 0)
        return -1;
    for (attempt = 0; attempt < 16; attempt++) {
        if (RAND_bytes(random, sizeof(random)) != 1 ||
            snprintf(temporary, sizeof(temporary), "%s/.%s.tmp-%ld-%02x%02x%02x%02x",
                     directory, name, (long)getpid(), random[0], random[1],
                     random[2], random[3]) >= (int)sizeof(temporary))
            goto done;
        fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                             O_NOFOLLOW, 0600);
        if (fd >= 0)
            break;
        if (errno != EEXIST)
            goto done;
    }
    if (fd < 0 || apd_credentials_file_status(fd, 0600, 0, &status) != 0 ||
        apd_credentials_write_all(fd, data, length) != 0 || fsync(fd) != 0 ||
        close(fd) != 0)
        goto done_unclosed;
    fd = -1;
    if (rename(temporary, destination) != 0 ||
        apd_credentials_parent_sync(directory) != 0)
        goto done;
    rc = 0;
done_unclosed:
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
done:
    if (rc != 0 && temporary[0])
        unlink(temporary);
    OPENSSL_cleanse(random, sizeof(random));
    return rc;
}

static int apd_credentials_bootstrap_parse(const unsigned char *data,
                                           size_t data_len,
                                           const char *directory,
                                           struct apd_bootstrap_config *out)
{
    static const char *const keys[] = {
        "version", "controller_host", "controller_port", "controller_id",
        "token_id", "token", "site_id", "hardware_digest",
        "ca_cert_pem_path"
    };
    struct apd_json_object object;
    int64_t version;
    int64_t port;

    if (!out || apd_json_parse(data, data_len, &object) != 0 ||
        apd_json_known(&object, keys, sizeof(keys) / sizeof(keys[0])) != 0)
        return -1;
    memset(out, 0, sizeof(*out));
    if (apd_json_get_integer(&object, "version", &version) != 0 || version != 1 ||
        apd_json_get_integer(&object, "controller_port", &port) != 0 ||
        port < 1 || port > 65535 ||
        apd_json_get_string(&object, "controller_host", out->controller_host,
                            sizeof(out->controller_host), 1) != 0 ||
        apd_json_get_string(&object, "controller_id", out->controller_id,
                            sizeof(out->controller_id), 0) != 0 ||
        apd_json_get_string(&object, "token_id", out->token_id,
                            sizeof(out->token_id), 1) != 0 ||
        apd_json_get_string(&object, "token", out->token,
                            sizeof(out->token), 1) != 0 ||
        apd_json_get_string(&object, "site_id", out->site_id,
                            sizeof(out->site_id), 1) != 0 ||
        apd_json_get_string(&object, "hardware_digest", out->hardware_digest,
                            sizeof(out->hardware_digest), 0) != 0 ||
        apd_json_get_string(&object, "ca_cert_pem_path", out->ca_cert_pem_path,
                            sizeof(out->ca_cert_pem_path), 0) != 0)
        goto fail;
    out->version = 1;
    out->controller_port = (uint16_t)port;
    out->controller_id_present = out->controller_id[0] != '\0';
    if (!out->ca_cert_pem_path[0] &&
        apd_credentials_path(out->ca_cert_pem_path,
                             sizeof(out->ca_cert_pem_path), directory,
                             APD_CREDENTIALS_CA_FILE) != 0)
        goto fail;
    if (!apd_credentials_host(out->controller_host) ||
        (out->controller_id_present &&
         !apd_credentials_controller_id(out->controller_id)) ||
        !apd_credentials_uuid(out->token_id) ||
        !apd_credentials_token(out->token) ||
        !apd_credentials_printable(out->site_id, APD_CREDENTIALS_SITE_MAX, 1) ||
        !apd_credentials_digest(out->hardware_digest, 1) ||
        out->ca_cert_pem_path[0] != '/' ||
        !apd_credentials_printable(out->ca_cert_pem_path, PATH_MAX - 1, 0))
        goto fail;
    return 0;
fail:
    apd_credentials_bootstrap_cleanse(out);
    return -1;
}

static int apd_credentials_bootstrap_load_locked(
    const struct apd_credentials_lock *lock, struct apd_bootstrap_config *out)
{
    unsigned char *data = NULL;
    unsigned char *ca_der = NULL;
    size_t data_len = 0;
    size_t ca_der_len = 0;
    char ca_fingerprint[APD_CREDENTIALS_DIGEST_LEN + 1] = {0};
    char path[PATH_MAX];
    X509 *ca = NULL;
    int rc = -1;

    if (!lock || !out ||
        apd_credentials_path(path, sizeof(path), lock->directory,
                             APD_CREDENTIALS_BOOTSTRAP_FILE) != 0 ||
        apd_credentials_read_secure(path, APD_CREDENTIALS_JSON_MAX,
                                    &data, &data_len) != 0)
        return -1;
    rc = apd_credentials_bootstrap_parse(data, data_len, lock->directory, out);
    if (rc == 0) {
        ca = apd_credentials_ca_open(out->ca_cert_pem_path, &ca_der,
                                     &ca_der_len, ca_fingerprint);
        if (!ca) {
            apd_credentials_bootstrap_cleanse(out);
            rc = -1;
        }
    }
    X509_free(ca);
    if (ca_der) {
        OPENSSL_cleanse(ca_der, ca_der_len);
        free(ca_der);
    }
    OPENSSL_cleanse(ca_fingerprint, sizeof(ca_fingerprint));
    OPENSSL_cleanse(data, data_len);
    free(data);
    return rc;
}

int apd_credentials_bootstrap_load(struct apd_bootstrap_config *out)
{
    struct apd_credentials_lock lock;
    int rc;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (apd_credentials_lock_open(&lock) != 0)
        return -1;
    rc = apd_credentials_bootstrap_load_locked(&lock, out);
    apd_credentials_lock_close(&lock);
    return rc;
}

static int apd_credentials_sha256(const unsigned char *data, size_t length,
                                  char out[APD_CREDENTIALS_DIGEST_LEN + 1])
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    size_t i;

    if (!data || !length || !SHA256(data, length, digest))
        return -1;
    memcpy(out, "sha256:", 7);
    for (i = 0; i < sizeof(digest); i++)
        snprintf(out + 7 + i * 2, 3, "%02x", digest[i]);
    out[APD_CREDENTIALS_DIGEST_LEN] = '\0';
    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

static int64_t apd_credentials_days_from_civil(int year, unsigned int month,
                                               unsigned int day)
{
    int adjusted_month;
    int era;
    unsigned int year_of_era;
    unsigned int day_of_year;
    unsigned int day_of_era;

    year -= month <= 2;
    era = (year >= 0 ? year : year - 399) / 400;
    year_of_era = (unsigned int)(year - era * 400);
    adjusted_month = (int)month + (month > 2 ? -3 : 9);
    day_of_year = (153 * (unsigned int)adjusted_month + 2) /
                  5 + day - 1;
    day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 +
                 day_of_year;
    return (int64_t)era * 146097 + (int64_t)day_of_era - 719468;
}

static int apd_credentials_asn1_epoch(const ASN1_TIME *value, int64_t *out)
{
    struct tm time_value;
    int64_t days;

    memset(&time_value, 0, sizeof(time_value));
    if (!value || !out || ASN1_TIME_to_tm(value, &time_value) != 1 ||
        time_value.tm_mon < 0 || time_value.tm_mon > 11 ||
        time_value.tm_mday < 1 || time_value.tm_mday > 31)
        return -1;
    days = apd_credentials_days_from_civil(time_value.tm_year + 1900,
                                           (unsigned int)time_value.tm_mon + 1,
                                           (unsigned int)time_value.tm_mday);
    *out = days * 86400 + time_value.tm_hour * 3600 +
           time_value.tm_min * 60 + time_value.tm_sec;
    return 0;
}

static int apd_credentials_certificate_serial(X509 *certificate,
                                              char *out, size_t out_size)
{
    BIGNUM *number = NULL;
    char *hex = NULL;
    size_t i;
    size_t length;
    int rc = -1;

    number = ASN1_INTEGER_to_BN(X509_get_serialNumber(certificate), NULL);
    if (!number || BN_is_negative(number))
        goto done;
    hex = BN_bn2hex(number);
    if (!hex || !(length = strlen(hex)) || length >= out_size)
        goto done;
    for (i = 0; i < length; i++)
        out[i] = hex[i] >= 'A' && hex[i] <= 'F' ? (char)(hex[i] + 32) : hex[i];
    out[length] = '\0';
    rc = 0;
done:
    OPENSSL_free(hex);
    BN_free(number);
    return rc;
}

static X509 *apd_credentials_ca_open(const char *path,
                                     unsigned char **der, size_t *der_len,
                                     char fingerprint[APD_CREDENTIALS_DIGEST_LEN + 1])
{
    unsigned char *pem = NULL;
    unsigned char *encoded = NULL;
    unsigned char *cursor;
    size_t pem_len = 0;
    BIO *bio = NULL;
    X509 *ca = NULL;
    int length = 0;

    *der = NULL;
    *der_len = 0;
    if (apd_credentials_read_secure(path, APD_CREDENTIALS_CERT_MAX,
                                    &pem, &pem_len) != 0)
        goto fail;
    bio = BIO_new_mem_buf(pem, (int)pem_len);
    if (!bio)
        goto fail;
    ca = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!ca || X509_check_ca(ca) <= 0)
        goto fail;
    length = i2d_X509(ca, NULL);
    if (length <= 0 || length > APD_CREDENTIALS_CERT_MAX)
        goto fail;
    encoded = malloc((size_t)length);
    if (!encoded)
        goto fail;
    cursor = encoded;
    if (i2d_X509(ca, &cursor) != length ||
        apd_credentials_sha256(encoded, (size_t)length, fingerprint) != 0)
        goto fail;
    *der = encoded;
    *der_len = (size_t)length;
    encoded = NULL;
    BIO_free(bio);
    OPENSSL_cleanse(pem, pem_len);
    free(pem);
    return ca;
fail:
    BIO_free(bio);
    X509_free(ca);
    if (pem) {
        OPENSSL_cleanse(pem, pem_len);
        free(pem);
    }
    if (encoded) {
        OPENSSL_cleanse(encoded, (size_t)(length > 0 ? length : 0));
        free(encoded);
    }
    return NULL;
}

static int apd_credentials_unique_uri(X509 *certificate, const char *ap_id)
{
    GENERAL_NAMES *names = NULL;
    GENERAL_NAME *name;
    char expected[sizeof("urn:dreamingwrt:ap:") + APD_AP_ID_LEN];
    const unsigned char *uri;
    int uri_len;
    int rc = -1;

    if (snprintf(expected, sizeof(expected), "urn:dreamingwrt:ap:%s", ap_id) >=
        (int)sizeof(expected))
        return -1;
    names = X509_get_ext_d2i(certificate, NID_subject_alt_name, NULL, NULL);
    if (!names || sk_GENERAL_NAME_num(names) != 1)
        goto done;
    name = sk_GENERAL_NAME_value(names, 0);
    if (!name || name->type != GEN_URI)
        goto done;
    uri = ASN1_STRING_get0_data(name->d.uniformResourceIdentifier);
    uri_len = ASN1_STRING_length(name->d.uniformResourceIdentifier);
    if (uri_len != (int)strlen(expected) || memchr(uri, '\0', (size_t)uri_len) ||
        CRYPTO_memcmp(uri, expected, (size_t)uri_len) != 0)
        goto done;
    rc = 0;
done:
    GENERAL_NAMES_free(names);
    OPENSSL_cleanse(expected, sizeof(expected));
    return rc;
}

static int apd_credentials_client_eku(X509 *certificate)
{
    EXTENDED_KEY_USAGE *usage =
        X509_get_ext_d2i(certificate, NID_ext_key_usage, NULL, NULL);
    ASN1_OBJECT *purpose;
    int rc = -1;

    if (!usage || sk_ASN1_OBJECT_num(usage) != 1)
        goto done;
    purpose = sk_ASN1_OBJECT_value(usage, 0);
    if (purpose && OBJ_obj2nid(purpose) == NID_client_auth)
        rc = 0;
done:
    EXTENDED_KEY_USAGE_free(usage);
    return rc;
}

static int apd_credentials_non_ca(X509 *certificate)
{
    BASIC_CONSTRAINTS *constraints =
        X509_get_ext_d2i(certificate, NID_basic_constraints, NULL, NULL);
    int rc = !constraints || !constraints->ca ? 0 : -1;

    BASIC_CONSTRAINTS_free(constraints);
    return rc;
}

static int apd_credentials_chain_verify(X509 *certificate, X509 *ca)
{
    X509_STORE *store = NULL;
    X509_STORE_CTX *context = NULL;
    int rc = -1;

    store = X509_STORE_new();
    context = X509_STORE_CTX_new();
    if (!store || !context || X509_STORE_add_cert(store, ca) != 1 ||
        X509_STORE_CTX_init(context, store, certificate, NULL) != 1 ||
        X509_verify_cert(context) != 1)
        goto done;
    rc = 0;
done:
    X509_STORE_CTX_free(context);
    X509_STORE_free(store);
    return rc;
}

static int apd_credentials_certificate_validate(
    const unsigned char *der, size_t der_len, const char *ca_path,
    struct apd_enrollment_metadata *metadata)
{
    struct apd_node_identity identity;
    const unsigned char *cursor = der;
    unsigned char public_key[APD_ED25519_KEY_LEN];
    unsigned char identity_public_key[APD_ED25519_KEY_LEN];
    unsigned char *ca_der = NULL;
    size_t public_key_len = sizeof(public_key);
    size_t identity_public_key_len = sizeof(identity_public_key);
    size_t ca_der_len = 0;
    EVP_PKEY *certificate_key = NULL;
    EVP_PKEY *identity_key = NULL;
    X509 *certificate = NULL;
    X509 *ca = NULL;
    int rc = -1;

    memset(&identity, 0, sizeof(identity));
    memset(public_key, 0, sizeof(public_key));
    memset(identity_public_key, 0, sizeof(identity_public_key));
    if (!der || !der_len || der_len > APD_CREDENTIALS_CERT_MAX || !metadata ||
        apd_db_identity_get(&identity) != 0)
        goto done;
    identity_key = apd_identity_key_open();
    certificate = d2i_X509(NULL, &cursor, (long)der_len);
    ca = apd_credentials_ca_open(ca_path, &ca_der, &ca_der_len,
                                 metadata->ca_fingerprint);
    if (!identity_key || !certificate || cursor != der + der_len || !ca ||
        X509_check_ca(certificate) > 0 ||
        apd_credentials_non_ca(certificate) != 0 ||
        X509_cmp_current_time(X509_get0_notBefore(certificate)) > 0 ||
        X509_cmp_current_time(X509_get0_notAfter(certificate)) < 0 ||
        apd_credentials_unique_uri(certificate, identity.ap_id) != 0 ||
        apd_credentials_client_eku(certificate) != 0 ||
        apd_credentials_chain_verify(certificate, ca) != 0)
        goto done;
    certificate_key = X509_get_pubkey(certificate);
    if (!certificate_key || EVP_PKEY_base_id(certificate_key) != EVP_PKEY_ED25519 ||
        EVP_PKEY_get_raw_public_key(identity_key, identity_public_key,
                                    &identity_public_key_len) <= 0 ||
        identity_public_key_len != sizeof(identity_public_key) ||
        EVP_PKEY_get_raw_public_key(certificate_key, public_key,
                                    &public_key_len) <= 0 ||
        public_key_len != sizeof(public_key) ||
        CRYPTO_memcmp(identity_public_key, identity.public_key,
                      sizeof(identity_public_key)) != 0 ||
        CRYPTO_memcmp(public_key, identity_public_key,
                      sizeof(public_key)) != 0 ||
        CRYPTO_memcmp(public_key, identity.public_key,
                      sizeof(public_key)) != 0 ||
        apd_credentials_certificate_serial(certificate, metadata->serial,
                                           sizeof(metadata->serial)) != 0 ||
        apd_credentials_asn1_epoch(X509_get0_notBefore(certificate),
                                   &metadata->not_before) != 0 ||
        apd_credentials_asn1_epoch(X509_get0_notAfter(certificate),
                                   &metadata->not_after) != 0 ||
        apd_credentials_sha256(der, der_len,
                               metadata->certificate_fingerprint) != 0)
        goto done;
    apd_credentials_copy(metadata->ap_id, sizeof(metadata->ap_id), identity.ap_id);
    apd_credentials_copy(metadata->ca_cert_pem_path,
                         sizeof(metadata->ca_cert_pem_path), ca_path);
    rc = 0;
done:
    EVP_PKEY_free(certificate_key);
    EVP_PKEY_free(identity_key);
    X509_free(certificate);
    X509_free(ca);
    if (ca_der) {
        OPENSSL_cleanse(ca_der, ca_der_len);
        free(ca_der);
    }
    OPENSSL_cleanse(public_key, sizeof(public_key));
    OPENSSL_cleanse(identity_public_key, sizeof(identity_public_key));
    OPENSSL_cleanse(&identity, sizeof(identity));
    return rc;
}

static int apd_json_escape(char *out, size_t out_size, size_t *offset,
                           const char *value)
{
    const unsigned char *cursor = (const unsigned char *)value;

    if (*offset >= out_size || out_size - *offset < 2)
        return -1;
    out[(*offset)++] = '"';
    while (*cursor) {
        if (*cursor < 0x20 || *cursor > 0x7e)
            return -1;
        if (*cursor == '"' || *cursor == '\\') {
            if (*offset >= out_size || out_size - *offset < 2)
                return -1;
            out[(*offset)++] = '\\';
        }
        if (*offset >= out_size || out_size - *offset < 1)
            return -1;
        out[(*offset)++] = (char)*cursor++;
    }
    if (*offset >= out_size || out_size - *offset < 1)
        return -1;
    out[(*offset)++] = '"';
    return 0;
}

static int apd_credentials_metadata_encode(
    const struct apd_enrollment_metadata *metadata,
    unsigned char *out, size_t out_size, size_t *out_len)
{
    static const char *const keys[] = {
        "controller_id", "controller_host", "enrollment_id", "certificate_id",
        "ap_id", "serial",
        "certificate_fingerprint", "ca_fingerprint", "ca_cert_pem_path", "state"
    };
    const char *values[] = {
        metadata->controller_id, metadata->controller_host,
        metadata->enrollment_id, metadata->certificate_id, metadata->ap_id,
        metadata->serial, metadata->certificate_fingerprint,
        metadata->ca_fingerprint, metadata->ca_cert_pem_path, metadata->state
    };
    char buffer[APD_CREDENTIALS_JSON_MAX];
    size_t offset = 0;
    size_t i;
    int count;

    count = snprintf(buffer, sizeof(buffer), "{\"version\":1");
    if (count < 0 || (size_t)count >= sizeof(buffer))
        return -1;
    offset = (size_t)count;
    for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        count = snprintf(buffer + offset, sizeof(buffer) - offset, ",\"%s\":", keys[i]);
        if (count < 0 || (size_t)count >= sizeof(buffer) - offset)
            return -1;
        offset += (size_t)count;
        if (apd_json_escape(buffer, sizeof(buffer), &offset, values[i]) != 0)
            return -1;
    }
    count = snprintf(buffer + offset, sizeof(buffer) - offset,
                     ",\"controller_port\":%u,\"not_before\":%lld,\"not_after\":%lld}\n",
                     (unsigned int)metadata->controller_port,
                     (long long)metadata->not_before,
                     (long long)metadata->not_after);
    if (count < 0 || (size_t)count >= sizeof(buffer) - offset)
        return -1;
    offset += (size_t)count;
    if (offset > out_size)
        return -1;
    memcpy(out, buffer, offset);
    *out_len = offset;
    OPENSSL_cleanse(buffer, sizeof(buffer));
    return 0;
}

static int apd_credentials_metadata_parse(const unsigned char *data,
                                          size_t data_len,
                                          struct apd_enrollment_metadata *out)
{
    static const char *const keys[] = {
        "version", "controller_id", "controller_host", "controller_port",
        "enrollment_id", "certificate_id", "ap_id", "serial", "not_before",
        "not_after", "certificate_fingerprint",
        "ca_fingerprint", "ca_cert_pem_path", "state"
    };
    struct apd_json_object object;
    int64_t version;
    int64_t controller_port;

    if (!out || apd_json_parse(data, data_len, &object) != 0 ||
        apd_json_known(&object, keys, sizeof(keys) / sizeof(keys[0])) != 0 ||
        object.count != sizeof(keys) / sizeof(keys[0]))
        return -1;
    memset(out, 0, sizeof(*out));
    if (apd_json_get_integer(&object, "version", &version) != 0 || version != 1 ||
        apd_json_get_string(&object, "controller_id", out->controller_id,
                            sizeof(out->controller_id), 1) != 0 ||
        apd_json_get_string(&object, "controller_host", out->controller_host,
                            sizeof(out->controller_host), 1) != 0 ||
        apd_json_get_integer(&object, "controller_port", &controller_port) != 0 ||
        controller_port < 1 || controller_port > 65535 ||
        apd_json_get_string(&object, "enrollment_id", out->enrollment_id,
                            sizeof(out->enrollment_id), 1) != 0 ||
        apd_json_get_string(&object, "certificate_id", out->certificate_id,
                            sizeof(out->certificate_id), 1) != 0 ||
        apd_json_get_string(&object, "ap_id", out->ap_id,
                            sizeof(out->ap_id), 1) != 0 ||
        apd_json_get_string(&object, "serial", out->serial,
                            sizeof(out->serial), 1) != 0 ||
        apd_json_get_integer(&object, "not_before", &out->not_before) != 0 ||
        apd_json_get_integer(&object, "not_after", &out->not_after) != 0 ||
        apd_json_get_string(&object, "certificate_fingerprint",
                            out->certificate_fingerprint,
                            sizeof(out->certificate_fingerprint), 1) != 0 ||
        apd_json_get_string(&object, "ca_fingerprint", out->ca_fingerprint,
                            sizeof(out->ca_fingerprint), 1) != 0 ||
        apd_json_get_string(&object, "ca_cert_pem_path", out->ca_cert_pem_path,
                            sizeof(out->ca_cert_pem_path), 1) != 0 ||
        apd_json_get_string(&object, "state", out->state,
                            sizeof(out->state), 1) != 0)
        goto fail;
    out->version = 1;
    out->controller_port = (uint16_t)controller_port;
    if (!apd_credentials_controller_id(out->controller_id) ||
        !apd_credentials_host(out->controller_host) ||
        !apd_credentials_uuid(out->enrollment_id) ||
        !apd_credentials_uuid(out->certificate_id) ||
        !apd_credentials_uuid(out->ap_id) ||
        !apd_credentials_serial(out->serial) ||
        out->not_before >= out->not_after ||
        !apd_credentials_digest(out->certificate_fingerprint, 0) ||
        !apd_credentials_digest(out->ca_fingerprint, 0) ||
        out->ca_cert_pem_path[0] != '/' ||
        !apd_credentials_printable(out->ca_cert_pem_path, PATH_MAX - 1, 0) ||
        (strcmp(out->state, APD_CREDENTIALS_STATE_PENDING) != 0 &&
         strcmp(out->state, APD_CREDENTIALS_STATE_ADOPTED) != 0))
        goto fail;
    return 0;
fail:
    apd_credentials_metadata_cleanse(out);
    return -1;
}

static int apd_credentials_metadata_load_locked(
    const struct apd_credentials_lock *lock, struct apd_enrollment_metadata *out)
{
    unsigned char *data = NULL;
    size_t data_len = 0;
    char path[PATH_MAX];
    int rc = -1;

    if (apd_credentials_path(path, sizeof(path), lock->directory,
                             APD_CREDENTIALS_METADATA_FILE) != 0 ||
        apd_credentials_read_secure(path, APD_CREDENTIALS_JSON_MAX,
                                    &data, &data_len) != 0)
        return -1;
    rc = apd_credentials_metadata_parse(data, data_len, out);
    OPENSSL_cleanse(data, data_len);
    free(data);
    return rc;
}

static int apd_credentials_metadata_write_locked(
    const struct apd_credentials_lock *lock,
    const struct apd_enrollment_metadata *metadata)
{
    unsigned char encoded[APD_CREDENTIALS_JSON_MAX];
    size_t encoded_len = 0;
    int rc;

    memset(encoded, 0, sizeof(encoded));
    if (apd_credentials_metadata_encode(metadata, encoded, sizeof(encoded),
                                        &encoded_len) != 0)
        return -1;
    rc = apd_credentials_atomic_write(lock->directory,
                                      APD_CREDENTIALS_METADATA_FILE,
                                      encoded, encoded_len);
    OPENSSL_cleanse(encoded, sizeof(encoded));
    return rc;
}

static int apd_credentials_metadata_equal(
    const struct apd_enrollment_metadata *left,
    const struct apd_enrollment_metadata *right, int compare_state)
{
    return left && right &&
           strcmp(left->controller_id, right->controller_id) == 0 &&
           strcmp(left->controller_host, right->controller_host) == 0 &&
           left->controller_port == right->controller_port &&
           strcmp(left->enrollment_id, right->enrollment_id) == 0 &&
           strcmp(left->certificate_id, right->certificate_id) == 0 &&
           strcmp(left->ap_id, right->ap_id) == 0 &&
           strcmp(left->serial, right->serial) == 0 &&
           left->not_before == right->not_before &&
           left->not_after == right->not_after &&
           strcmp(left->certificate_fingerprint,
                  right->certificate_fingerprint) == 0 &&
           strcmp(left->ca_fingerprint, right->ca_fingerprint) == 0 &&
           strcmp(left->ca_cert_pem_path, right->ca_cert_pem_path) == 0 &&
           (!compare_state || strcmp(left->state, right->state) == 0);
}

static int apd_credentials_existing_cert_locked(
    const struct apd_credentials_lock *lock, const unsigned char *der,
    size_t der_len, int *present)
{
    unsigned char *existing = NULL;
    size_t existing_len = 0;
    char path[PATH_MAX];

    *present = 0;
    if (apd_credentials_path(path, sizeof(path), lock->directory,
                             APD_CREDENTIALS_CERT_FILE) != 0)
        return -1;
    if (apd_credentials_read_binary_secure(path, APD_CREDENTIALS_CERT_MAX,
                                           &existing, &existing_len) != 0) {
        if (apd_credentials_path_absent(path))
            return 0;
        return -1;
    }
    *present = 1;
    if (existing_len != der_len || CRYPTO_memcmp(existing, der, der_len) != 0) {
        OPENSSL_cleanse(existing, existing_len);
        free(existing);
        return -1;
    }
    OPENSSL_cleanse(existing, existing_len);
    free(existing);
    return 0;
}

int apd_credentials_certificate_store(
    const struct apd_credentials_certificate_input *input,
    struct apd_enrollment_metadata *out)
{
    struct apd_credentials_lock lock;
    struct apd_bootstrap_config bootstrap;
    struct apd_enrollment_metadata candidate;
    struct apd_enrollment_metadata existing;
    int cert_present = 0;
    int metadata_present = 0;
    int rc = -1;

    memset(&bootstrap, 0, sizeof(bootstrap));
    memset(&candidate, 0, sizeof(candidate));
    memset(&existing, 0, sizeof(existing));
    if (out)
        memset(out, 0, sizeof(*out));
    if (!input || !input->certificate_der || !input->certificate_der_len ||
        !apd_credentials_controller_id(input->controller_id) ||
        !apd_credentials_uuid(input->enrollment_id) ||
        !apd_credentials_uuid(input->certificate_id) ||
        apd_credentials_lock_open(&lock) != 0)
        goto done;
    if (apd_credentials_bootstrap_load_locked(&lock, &bootstrap) != 0 ||
        (bootstrap.controller_id_present &&
         strcmp(bootstrap.controller_id, input->controller_id) != 0))
        goto done_locked;
    candidate.version = 1;
    apd_credentials_copy(candidate.controller_id, sizeof(candidate.controller_id),
                         input->controller_id);
    apd_credentials_copy(candidate.controller_host,
                         sizeof(candidate.controller_host),
                         bootstrap.controller_host);
    candidate.controller_port = bootstrap.controller_port;
    apd_credentials_copy(candidate.enrollment_id, sizeof(candidate.enrollment_id),
                         input->enrollment_id);
    apd_credentials_copy(candidate.certificate_id,
                         sizeof(candidate.certificate_id), input->certificate_id);
    apd_credentials_copy(candidate.state, sizeof(candidate.state),
                         APD_CREDENTIALS_STATE_PENDING);
    if (apd_credentials_certificate_validate(input->certificate_der,
                                             input->certificate_der_len,
                                             bootstrap.ca_cert_pem_path,
                                             &candidate) != 0 ||
        apd_credentials_existing_cert_locked(&lock, input->certificate_der,
                                             input->certificate_der_len,
                                             &cert_present) != 0)
        goto done_locked;
    metadata_present =
        apd_credentials_metadata_load_locked(&lock, &existing) == 0;
    if (!metadata_present) {
        char metadata_path[PATH_MAX];

        if (apd_credentials_path(metadata_path, sizeof(metadata_path),
                                 lock.directory,
                                 APD_CREDENTIALS_METADATA_FILE) != 0 ||
            !apd_credentials_path_absent(metadata_path))
            goto done_locked;
    }
    if (metadata_present) {
        if (!cert_present)
            goto done_locked;
        if (!apd_credentials_metadata_equal(&candidate, &existing, 0))
            goto done_locked;
        if (out)
            *out = existing;
        rc = 0;
        goto done_locked;
    }
    if (!cert_present &&
        apd_credentials_atomic_write(lock.directory,
                                     APD_CREDENTIALS_CERT_FILE,
                                     input->certificate_der,
                                     input->certificate_der_len) != 0)
        goto done_locked;
    if (apd_credentials_metadata_write_locked(&lock, &candidate) != 0)
        goto done_locked;
    if (out)
        *out = candidate;
    rc = 0;
done_locked:
    apd_credentials_lock_close(&lock);
done:
    apd_credentials_bootstrap_cleanse(&bootstrap);
    apd_credentials_metadata_cleanse(&candidate);
    apd_credentials_metadata_cleanse(&existing);
    return rc;
}

static int apd_credentials_validate_locked(
    const struct apd_credentials_lock *lock,
    struct apd_enrollment_metadata *out)
{
    struct apd_enrollment_metadata *stored = NULL;
    struct apd_enrollment_metadata *verified = NULL;
    unsigned char *der = NULL;
    size_t der_len = 0;
    char path[PATH_MAX];
    int rc = -1;

    stored = calloc(1, sizeof(*stored));
    verified = calloc(1, sizeof(*verified));
    if (!stored || !verified ||
        apd_credentials_metadata_load_locked(lock, stored) != 0 ||
        apd_credentials_path(path, sizeof(path), lock->directory,
                             APD_CREDENTIALS_CERT_FILE) != 0 ||
        apd_credentials_read_binary_secure(path, APD_CREDENTIALS_CERT_MAX,
                                           &der, &der_len) != 0 ||
        apd_credentials_certificate_validate(der, der_len,
                                             stored->ca_cert_pem_path,
                                             verified) != 0)
        goto done;
    apd_credentials_copy(verified->controller_id,
                         sizeof(verified->controller_id),
                         stored->controller_id);
    apd_credentials_copy(verified->controller_host,
                         sizeof(verified->controller_host),
                         stored->controller_host);
    verified->controller_port = stored->controller_port;
    apd_credentials_copy(verified->enrollment_id,
                         sizeof(verified->enrollment_id),
                         stored->enrollment_id);
    apd_credentials_copy(verified->certificate_id,
                         sizeof(verified->certificate_id),
                         stored->certificate_id);
    apd_credentials_copy(verified->state, sizeof(verified->state),
                         stored->state);
    if (!apd_credentials_metadata_equal(stored, verified, 1))
        goto done;
    if (strcmp(stored->state, APD_CREDENTIALS_STATE_ADOPTED) == 0) {
        if (apd_credentials_path(path, sizeof(path), lock->directory,
                                 APD_CREDENTIALS_BOOTSTRAP_FILE) != 0)
            goto done;
        if (lstat(path, &(struct stat){0}) == 0 || errno != ENOENT)
            goto done;
    }
    if (out)
        *out = *stored;
    rc = 0;
done:
    if (der) {
        OPENSSL_cleanse(der, der_len);
        free(der);
    }
    if (stored) {
        apd_credentials_metadata_cleanse(stored);
        free(stored);
    }
    if (verified) {
        apd_credentials_metadata_cleanse(verified);
        free(verified);
    }
    return rc;
}

int apd_credentials_validate_startup(struct apd_enrollment_metadata *out)
{
    struct apd_credentials_lock lock;
    int rc;

    if (out)
        memset(out, 0, sizeof(*out));
    if (apd_credentials_lock_open(&lock) != 0)
        return -1;
    rc = apd_credentials_validate_locked(&lock, out);
    apd_credentials_lock_close(&lock);
    return rc;
}

/*
 * Overwrites a credential file with zeros, then unlinks it and syncs the
 * parent directory. Removal must not leave readable key material behind on
 * flash, so the shred happens before the unlink rather than after.
 *
 * Sets *removed to 1 when a file was actually destroyed and to 0 when it was
 * already absent, so callers can report what they really did instead of
 * claiming a deletion that never happened.
 */
static int apd_credentials_file_destroy_locked(
    const struct apd_credentials_lock *lock, const char *name,
    size_t maximum, int *removed)
{
    unsigned char zeros[4096];
    char path[PATH_MAX];
    struct stat status;
    off_t offset = 0;
    int fd;
    int rc = -1;

    if (removed)
        *removed = 0;
    memset(zeros, 0, sizeof(zeros));
    if (!lock || !name ||
        apd_credentials_path(path, sizeof(path), lock->directory, name) != 0)
        goto done;
    fd = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT)
            rc = 0;
        goto done;
    }
    if (apd_credentials_file_status(fd, 0600, maximum, &status) != 0)
        goto close_file;
    while (offset < status.st_size) {
        size_t amount = (size_t)(status.st_size - offset);
        if (amount > sizeof(zeros))
            amount = sizeof(zeros);
        if (apd_credentials_write_all(fd, zeros, amount) != 0)
            goto close_file;
        offset += (off_t)amount;
    }
    if (fsync(fd) != 0 || close(fd) != 0)
        goto done;
    fd = -1;
    if (unlink(path) != 0 || apd_credentials_parent_sync(lock->directory) != 0)
        goto done;
    if (removed)
        *removed = 1;
    rc = 0;
    goto done;
close_file:
    close(fd);
done:
    OPENSSL_cleanse(zeros, sizeof(zeros));
    return rc;
}

static int apd_credentials_bootstrap_remove_locked(
    const struct apd_credentials_lock *lock)
{
    return apd_credentials_file_destroy_locked(
        lock, APD_CREDENTIALS_BOOTSTRAP_FILE, APD_CREDENTIALS_JSON_MAX, NULL);
}

int apd_credentials_activate(
    const char *controller_id, const char *enrollment_id,
    const char *certificate_id,
    const unsigned char certificate_fingerprint[SHA256_DIGEST_LENGTH],
    struct apd_enrollment_metadata *out)
{
    struct apd_credentials_lock lock;
    struct apd_enrollment_metadata *metadata = NULL;
    char controller_id_copy[APD_CREDENTIALS_UUID_LEN + 1];
    char enrollment_id_copy[APD_CREDENTIALS_UUID_LEN + 1];
    char certificate_id_copy[APD_CREDENTIALS_UUID_LEN + 1];
    unsigned char certificate_fingerprint_copy[SHA256_DIGEST_LENGTH];
    char fingerprint[APD_CREDENTIALS_DIGEST_LEN + 1];
    size_t i;
    int rc = APD_CREDENTIALS_ACTIVATE_CONTROLLER_INVALID;

    memset(controller_id_copy, 0, sizeof(controller_id_copy));
    memset(enrollment_id_copy, 0, sizeof(enrollment_id_copy));
    memset(certificate_id_copy, 0, sizeof(certificate_id_copy));
    memset(certificate_fingerprint_copy, 0,
           sizeof(certificate_fingerprint_copy));
    memset(fingerprint, 0, sizeof(fingerprint));
    if (!apd_credentials_controller_id(controller_id))
        goto done;
    rc = APD_CREDENTIALS_ACTIVATE_ENROLLMENT_INVALID;
    if (!apd_credentials_uuid(enrollment_id))
        goto done;
    rc = APD_CREDENTIALS_ACTIVATE_CERTIFICATE_INVALID;
    if (!apd_credentials_uuid(certificate_id))
        goto done;
    rc = APD_CREDENTIALS_ACTIVATE_FINGERPRINT_MISSING;
    if (!certificate_fingerprint)
        goto done;
    apd_credentials_copy(controller_id_copy, sizeof(controller_id_copy),
                         controller_id);
    apd_credentials_copy(enrollment_id_copy, sizeof(enrollment_id_copy),
                         enrollment_id);
    apd_credentials_copy(certificate_id_copy, sizeof(certificate_id_copy),
                         certificate_id);
    memcpy(certificate_fingerprint_copy, certificate_fingerprint,
           sizeof(certificate_fingerprint_copy));
    if (out)
        memset(out, 0, sizeof(*out));
    metadata = calloc(1, sizeof(*metadata));
    if (!metadata) {
        rc = APD_CREDENTIALS_ACTIVATE_VALIDATE_FAILED;
        goto done;
    }
    memcpy(fingerprint, "sha256:", 7);
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(fingerprint + 7 + i * 2, 3, "%02x",
                 certificate_fingerprint_copy[i]);
    if (apd_credentials_lock_open(&lock) != 0) {
        rc = APD_CREDENTIALS_ACTIVATE_LOCK_FAILED;
        goto done;
    }
    if (apd_credentials_validate_locked(&lock, metadata) != 0) {
        rc = APD_CREDENTIALS_ACTIVATE_VALIDATE_FAILED;
        goto done_locked;
    }
    if (strcmp(metadata->controller_id, controller_id_copy) != 0 ||
        strcmp(metadata->enrollment_id, enrollment_id_copy) != 0 ||
        strcmp(metadata->certificate_id, certificate_id_copy) != 0 ||
        strcmp(metadata->certificate_fingerprint, fingerprint) != 0) {
        rc = APD_CREDENTIALS_ACTIVATE_BINDING_MISMATCH;
        goto done_locked;
    }
    if (strcmp(metadata->state, APD_CREDENTIALS_STATE_ADOPTED) == 0) {
        if (out)
            *out = *metadata;
        rc = APD_CREDENTIALS_ACTIVATE_OK;
        goto done_locked;
    }
    if (apd_credentials_bootstrap_remove_locked(&lock) != 0) {
        rc = APD_CREDENTIALS_ACTIVATE_BOOTSTRAP_REMOVE_FAILED;
        goto done_locked;
    }
    apd_credentials_copy(metadata->state, sizeof(metadata->state),
                         APD_CREDENTIALS_STATE_ADOPTED);
#ifdef APD_CREDENTIALS_TEST_STANDALONE
    if (getenv("APD_CREDENTIALS_TEST_FAIL_ADOPT_COMMIT_ONCE"))
        goto done_locked;
#endif
    if (apd_credentials_metadata_write_locked(&lock, metadata) != 0) {
        rc = APD_CREDENTIALS_ACTIVATE_METADATA_COMMIT_FAILED;
        goto done_locked;
    }
    if (out)
        *out = *metadata;
    rc = APD_CREDENTIALS_ACTIVATE_OK;
done_locked:
    apd_credentials_lock_close(&lock);
done:
    if (metadata) {
        apd_credentials_metadata_cleanse(metadata);
        free(metadata);
    }
    OPENSSL_cleanse(controller_id_copy, sizeof(controller_id_copy));
    OPENSSL_cleanse(enrollment_id_copy, sizeof(enrollment_id_copy));
    OPENSSL_cleanse(certificate_id_copy, sizeof(certificate_id_copy));
    OPENSSL_cleanse(certificate_fingerprint_copy,
                    sizeof(certificate_fingerprint_copy));
    OPENSSL_cleanse(fingerprint, sizeof(fingerprint));
    return rc;
}

/*
 * Reverses adoption: destroys the client certificate, the enrollment sidecar
 * and any leftover bootstrap file under the same lock the store/activate
 * paths take, so an unpair cannot interleave with a credential write.
 *
 * Order matters. The certificate goes first: a surviving certificate with no
 * enrollment.json is an orphan that validate_startup rejects anyway, whereas
 * surviving metadata pointing at a deleted certificate would look adopted to
 * a reader that only parses the sidecar.
 *
 * Absent files are not an error. Unpair is the operation an operator reaches
 * for precisely when state is inconsistent, so it converges on "not adopted"
 * instead of refusing because one file was already gone.
 */
int apd_credentials_unpair(struct apd_credentials_unpair_report *out)
{
    struct apd_credentials_lock lock;
    int rc = APD_CREDENTIALS_UNPAIR_LOCK_FAILED;

    if (out)
        memset(out, 0, sizeof(*out));
    if (apd_credentials_lock_open(&lock) != 0)
        return rc;

    rc = APD_CREDENTIALS_UNPAIR_CERTIFICATE_FAILED;
    if (apd_credentials_file_destroy_locked(
            &lock, APD_CREDENTIALS_CERT_FILE, APD_CREDENTIALS_CERT_MAX,
            out ? &out->certificate_removed : NULL) != 0)
        goto done;

    rc = APD_CREDENTIALS_UNPAIR_METADATA_FAILED;
    if (apd_credentials_file_destroy_locked(
            &lock, APD_CREDENTIALS_METADATA_FILE, APD_CREDENTIALS_JSON_MAX,
            out ? &out->enrollment_removed : NULL) != 0)
        goto done;

    /*
     * A bootstrap file only exists before activation completes, so it is
     * usually already gone. Removing it keeps a stale one-shot token from
     * being replayed by the next transport cycle.
     */
    rc = APD_CREDENTIALS_UNPAIR_BOOTSTRAP_FAILED;
    if (apd_credentials_file_destroy_locked(
            &lock, APD_CREDENTIALS_BOOTSTRAP_FILE, APD_CREDENTIALS_JSON_MAX,
            out ? &out->bootstrap_removed : NULL) != 0)
        goto done;

    rc = APD_CREDENTIALS_UNPAIR_OK;
done:
    apd_credentials_lock_close(&lock);
    return rc;
}
