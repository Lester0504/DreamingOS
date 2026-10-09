/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE

#include "webd_tls_identity.h"

#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define WEBD_TLS_CERT_PATH "/etc/dreamingwrt/tls/console.crt"

static void webd_tls_hex_prefixed(char out[72], const unsigned char *digest,
                                  size_t digest_len)
{
    size_t i;

    memcpy(out, "sha256:", 7);
    for (i = 0; i < digest_len; i++)
        snprintf(out + 7 + i * 2, 3, "%02x", digest[i]);
    out[7 + digest_len * 2] = '\0';
}

static int webd_tls_asn1_time_epoch(const ASN1_TIME *value, int64_t *out)
{
    struct tm tm;

    if (!value || !out)
        return -1;
    memset(&tm, 0, sizeof(tm));
    if (ASN1_TIME_to_tm(value, &tm) != 1)
        return -1;
    *out = (int64_t)timegm(&tm);
    return *out == (int64_t)-1 ? -1 : 0;
}

static int webd_tls_add_san(struct json_object *array, const char *prefix,
                            const char *value)
{
    char item[320];

    if (!array || !prefix || !value || !value[0])
        return -1;
    if (snprintf(item, sizeof(item), "%s%s", prefix, value) >= (int)sizeof(item))
        return -1;
    json_object_array_add(array, json_object_new_string(item));
    return 0;
}

static void webd_tls_collect_sans(X509 *certificate, struct json_object *sans)
{
    GENERAL_NAMES *names;
    int i;

    if (!certificate || !sans)
        return;
    names = X509_get_ext_d2i(certificate, NID_subject_alt_name, NULL, NULL);
    if (!names)
        return;
    for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
        const GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);

        if (!name)
            continue;
        if (name->type == GEN_DNS) {
            const unsigned char *data = ASN1_STRING_get0_data(name->d.dNSName);
            int length = ASN1_STRING_length(name->d.dNSName);
            char dns[256];

            if (!data || length <= 0 || length >= (int)sizeof(dns) ||
                memchr(data, '\0', (size_t)length) != NULL)
                continue;
            memcpy(dns, data, (size_t)length);
            dns[length] = '\0';
            webd_tls_add_san(sans, "DNS:", dns);
        } else if (name->type == GEN_IPADD) {
            char address[INET6_ADDRSTRLEN];
            const unsigned char *data = ASN1_STRING_get0_data(name->d.iPAddress);
            int length = ASN1_STRING_length(name->d.iPAddress);

            if (!data || (length != 4 && length != 16))
                continue;
            if (inet_ntop(length == 4 ? AF_INET : AF_INET6, data,
                          address, sizeof(address)))
                webd_tls_add_san(sans, "IP:", address);
        }
    }
    GENERAL_NAMES_free(names);
}

static const char *webd_tls_key_algorithm(EVP_PKEY *key)
{
    char group[80];

    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_EC)
        return NULL;
    memset(group, 0, sizeof(group));
    if (EVP_PKEY_get_group_name(key, group, sizeof(group), NULL) != 1)
        return NULL;
    return !strcmp(group, "prime256v1") || !strcmp(group, "P-256")
        ? "ecdsa-p256" : NULL;
}

struct json_object *webd_tls_identity_from_certificate(const char *cert_path)
{
    FILE *file;
    X509 *certificate = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *spki_der = NULL;
    unsigned char *certificate_der = NULL;
    unsigned char spki_digest[SHA256_DIGEST_LENGTH];
    unsigned char certificate_digest[SHA256_DIGEST_LENGTH];
    int spki_len;
    int certificate_len;
    int64_t not_before;
    int64_t not_after;
    const char *algorithm;
    char spki_text[72];
    char certificate_text[72];
    struct json_object *identity = NULL;
    struct json_object *sans = NULL;

    if (!cert_path || !cert_path[0])
        return NULL;
    file = fopen(cert_path, "r");
    if (!file)
        return NULL;
    certificate = PEM_read_X509(file, NULL, NULL, NULL);
    fclose(file);
    if (!certificate)
        return NULL;

    key = X509_get_pubkey(certificate);
    algorithm = webd_tls_key_algorithm(key);
    if (!key || !algorithm ||
        webd_tls_asn1_time_epoch(X509_get0_notBefore(certificate), &not_before) != 0 ||
        webd_tls_asn1_time_epoch(X509_get0_notAfter(certificate), &not_after) != 0)
        goto fail;

    spki_len = i2d_PUBKEY(key, &spki_der);
    certificate_len = i2d_X509(certificate, &certificate_der);
    if (spki_len <= 0 || certificate_len <= 0 || !spki_der || !certificate_der ||
        !SHA256(spki_der, (size_t)spki_len, spki_digest) ||
        !SHA256(certificate_der, (size_t)certificate_len, certificate_digest))
        goto fail;
    webd_tls_hex_prefixed(spki_text, spki_digest, sizeof(spki_digest));
    webd_tls_hex_prefixed(certificate_text, certificate_digest, sizeof(certificate_digest));

    identity = json_object_new_object();
    sans = json_object_new_array();
    if (!identity || !sans)
        goto fail;
    json_object_object_add(identity, "version", json_object_new_int(1));
    json_object_object_add(identity, "pin_type", json_object_new_string("spki_sha256"));
    json_object_object_add(identity, "spki_sha256", json_object_new_string(spki_text));
    json_object_object_add(identity, "certificate_sha256", json_object_new_string(certificate_text));
    json_object_object_add(identity, "key_algorithm", json_object_new_string(algorithm));
    json_object_object_add(identity, "not_before", json_object_new_int64(not_before));
    json_object_object_add(identity, "not_after", json_object_new_int64(not_after));
    webd_tls_collect_sans(certificate, sans);
    json_object_object_add(identity, "sans", sans);
    json_object_object_add(identity, "rotation_state", json_object_new_string("stable"));

    OPENSSL_free(spki_der);
    OPENSSL_free(certificate_der);
    EVP_PKEY_free(key);
    X509_free(certificate);
    return identity;

fail:
    if (identity)
        json_object_put(identity);
    if (sans)
        json_object_put(sans);
    OPENSSL_free(spki_der);
    OPENSSL_free(certificate_der);
    EVP_PKEY_free(key);
    X509_free(certificate);
    return NULL;
}

void webd_tls_identity_attach(struct json_object *object)
{
    struct json_object *identity;

    if (!object)
        return;
    identity = webd_tls_identity_from_certificate(WEBD_TLS_CERT_PATH);
    if (identity) {
        json_object_object_add(object, "tls_identity", identity);
        return;
    }
    json_object_object_add(object, "tls_identity", NULL);
    json_object_object_add(object, "tls_identity_reason",
                           json_object_new_string(
                               access(WEBD_TLS_CERT_PATH, R_OK) == 0
                                   ? "tls_identity_malformed"
                                   : "tls_identity_unavailable"));
}
