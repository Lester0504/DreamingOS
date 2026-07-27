// SPDX-License-Identifier: GPL-2.0-or-later
#define APD_CREDENTIALS_TEST_STANDALONE
#include "../src/apd/apd_credentials.c"

static const char *fixture_ap_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
static const char *fixture_controller_id = "bbbbbbbb-bbbb-5bbb-8bbb-bbbbbbbbbbbb";
static const char *fixture_enrollment_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
static const char *fixture_certificate_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

static int fixture_path(char *out, size_t out_size, const char *name)
{
    return snprintf(out, out_size, "%s/%s", apd_credentials_pki_dir(), name) <
                   (int)out_size ? 0 : -1;
}

static int fixture_write(const char *path, const unsigned char *data,
                         size_t length)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                  0600);
    int rc = -1;

    if (fd >= 0 && fchmod(fd, 0600) == 0 &&
        apd_credentials_write_all(fd, data, length) == 0 && fsync(fd) == 0 &&
        close(fd) == 0)
        rc = 0;
    else if (fd >= 0)
        close(fd);
    return rc;
}

static EVP_PKEY *fixture_identity_key_load(void)
{
    unsigned char private_key[APD_ED25519_KEY_LEN];
    char path[PATH_MAX];
    int fd = -1;
    size_t offset = 0;
    EVP_PKEY *key = NULL;

    memset(private_key, 0, sizeof(private_key));
    if (fixture_path(path, sizeof(path), "identity.ed25519") != 0)
        goto done;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || apd_credentials_file_status(fd, 0600,
                                              sizeof(private_key), NULL) != 0)
        goto done;
    while (offset < sizeof(private_key)) {
        ssize_t count = read(fd, private_key + offset,
                             sizeof(private_key) - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            goto done;
        offset += (size_t)count;
    }
    if (read(fd, private_key, 1) != 0)
        goto done;
    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_key,
                                       sizeof(private_key));
done:
    if (fd >= 0)
        close(fd);
    OPENSSL_cleanse(private_key, sizeof(private_key));
    return key;
}

int apd_db_identity_get(struct apd_node_identity *out)
{
    EVP_PKEY *key = NULL;
    size_t length = APD_ED25519_KEY_LEN;
    int rc = -1;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    key = fixture_identity_key_load();
    if (!key || EVP_PKEY_get_raw_public_key(key, out->public_key, &length) <= 0 ||
        length != APD_ED25519_KEY_LEN)
        goto done;
    apd_credentials_copy(out->ap_id, sizeof(out->ap_id), fixture_ap_id);
    rc = 0;
done:
    EVP_PKEY_free(key);
    return rc;
}

EVP_PKEY *apd_identity_key_open(void)
{
    return fixture_identity_key_load();
}

static EVP_PKEY *fixture_ed25519_generate(void)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY *key = NULL;

    if (!context || EVP_PKEY_keygen_init(context) <= 0 ||
        EVP_PKEY_keygen(context, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static int fixture_extension(X509 *certificate, X509 *issuer, int nid,
                             const char *value)
{
    X509V3_CTX context;
    X509_EXTENSION *extension;
    int rc = -1;

    X509V3_set_ctx(&context, issuer, certificate, NULL, NULL, 0);
    extension = X509V3_EXT_conf_nid(NULL, &context, nid, (char *)value);
    if (extension && X509_add_ext(certificate, extension, -1) == 1)
        rc = 0;
    X509_EXTENSION_free(extension);
    return rc;
}

static int fixture_name(X509_NAME *name, const char *common_name)
{
    return X509_NAME_add_entry_by_NID(
               name, NID_commonName, MBSTRING_ASC,
               (const unsigned char *)common_name, -1, -1, 0) == 1 ? 0 : -1;
}

static X509 *fixture_ca_create(EVP_PKEY *key, const char *name)
{
    X509 *certificate = X509_new();
    X509_NAME *subject;

    if (!certificate || X509_set_version(certificate, 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1) != 1 ||
        X509_gmtime_adj(X509_getm_notBefore(certificate), -60) == NULL ||
        X509_gmtime_adj(X509_getm_notAfter(certificate), 86400) == NULL ||
        X509_set_pubkey(certificate, key) != 1)
        goto fail;
    subject = X509_get_subject_name(certificate);
    if (!subject || fixture_name(subject, name) != 0 ||
        X509_set_issuer_name(certificate, subject) != 1 ||
        fixture_extension(certificate, certificate, NID_basic_constraints,
                          "critical,CA:TRUE") != 0 ||
        fixture_extension(certificate, certificate, NID_key_usage,
                          "critical,keyCertSign,cRLSign") != 0 ||
        X509_sign(certificate, key, NULL) <= 0)
        goto fail;
    return certificate;
fail:
    X509_free(certificate);
    return NULL;
}

static X509 *fixture_client_create(EVP_PKEY *public_key, EVP_PKEY *issuer_key,
                                   X509 *issuer, const char *uri,
                                   int with_eku, int as_ca)
{
    static long serial = 100;
    X509 *certificate = X509_new();
    X509_NAME *subject;
    char san[256];

    if (!certificate || X509_set_version(certificate, 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(certificate), serial++) != 1 ||
        X509_gmtime_adj(X509_getm_notBefore(certificate), -60) == NULL ||
        X509_gmtime_adj(X509_getm_notAfter(certificate), 3600) == NULL ||
        X509_set_pubkey(certificate, public_key) != 1)
        goto fail;
    subject = X509_get_subject_name(certificate);
    if (!subject || fixture_name(subject, "DreamingWrt AP") != 0 ||
        X509_set_issuer_name(certificate, X509_get_subject_name(issuer)) != 1 ||
        snprintf(san, sizeof(san), "URI:%s", uri) >= (int)sizeof(san) ||
        fixture_extension(certificate, issuer, NID_subject_alt_name, san) != 0 ||
        fixture_extension(certificate, issuer, NID_basic_constraints,
                          as_ca ? "critical,CA:TRUE" : "critical,CA:FALSE") != 0 ||
        (with_eku && fixture_extension(certificate, issuer, NID_ext_key_usage,
                                       "critical,clientAuth") != 0) ||
        X509_sign(certificate, issuer_key, NULL) <= 0)
        goto fail;
    return certificate;
fail:
    X509_free(certificate);
    return NULL;
}

static int fixture_x509_der_write(const char *path, X509 *certificate)
{
    unsigned char *der = NULL;
    unsigned char *cursor;
    int length;
    int rc = -1;

    length = i2d_X509(certificate, NULL);
    if (length <= 0 || !(der = malloc((size_t)length)))
        return -1;
    cursor = der;
    if (i2d_X509(certificate, &cursor) == length)
        rc = fixture_write(path, der, (size_t)length);
    OPENSSL_cleanse(der, (size_t)length);
    free(der);
    return rc;
}

static int fixture_x509_pem_write(const char *path, X509 *certificate)
{
    BIO *bio = BIO_new(BIO_s_mem());
    BUF_MEM *buffer = NULL;
    int rc = -1;

    if (bio && PEM_write_bio_X509(bio, certificate) == 1) {
        BIO_get_mem_ptr(bio, &buffer);
        if (buffer && buffer->length > 0)
            rc = fixture_write(path, (const unsigned char *)buffer->data,
                               buffer->length);
    }
    BIO_free(bio);
    return rc;
}

static int fixture_setup(void)
{
    static const char bootstrap[] =
        "{\"version\":1,\"controller_host\":\"ac.example.test\"," 
        "\"controller_port\":9443,"
        "\"controller_id\":\"bbbbbbbb-bbbb-5bbb-8bbb-bbbbbbbbbbbb\"," 
        "\"token_id\":\"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee\","
        "\"token\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\","
        "\"site_id\":\"default\",\"hardware_digest\":\"\"}";
    unsigned char private_key[APD_ED25519_KEY_LEN];
    size_t private_key_len = sizeof(private_key);
    EVP_PKEY *identity = NULL;
    EVP_PKEY *wrong_identity = NULL;
    EVP_PKEY *ca_key = NULL;
    EVP_PKEY *other_ca_key = NULL;
    X509 *ca = NULL;
    X509 *other_ca = NULL;
    X509 *valid = NULL;
    X509 *wrong_key = NULL;
    X509 *wrong_san = NULL;
    X509 *no_eku = NULL;
    X509 *client_ca = NULL;
    X509 *untrusted = NULL;
    char uri[128];
    char path[PATH_MAX];
    int rc = -1;

    memset(private_key, 0, sizeof(private_key));
    if (apd_credentials_directory_validate(apd_credentials_pki_dir(), 1) != 0)
        return -1;
    identity = fixture_ed25519_generate();
    wrong_identity = fixture_ed25519_generate();
    ca_key = fixture_ed25519_generate();
    other_ca_key = fixture_ed25519_generate();
    ca = fixture_ca_create(ca_key, "DreamingWrt Controller CA");
    other_ca = fixture_ca_create(other_ca_key, "Other CA");
    if (!identity || !wrong_identity || !ca_key || !other_ca_key || !ca ||
        !other_ca || EVP_PKEY_get_raw_private_key(identity, private_key,
                                                  &private_key_len) <= 0 ||
        private_key_len != sizeof(private_key) ||
        snprintf(uri, sizeof(uri), "urn:dreamingwrt:ap:%s", fixture_ap_id) >=
            (int)sizeof(uri))
        goto done;
    valid = fixture_client_create(identity, ca_key, ca, uri, 1, 0);
    wrong_key = fixture_client_create(wrong_identity, ca_key, ca, uri, 1, 0);
    wrong_san = fixture_client_create(identity, ca_key, ca,
                                      "urn:dreamingwrt:ap:ffffffff-ffff-4fff-8fff-ffffffffffff",
                                      1, 0);
    no_eku = fixture_client_create(identity, ca_key, ca, uri, 0, 0);
    client_ca = fixture_client_create(identity, ca_key, ca, uri, 1, 1);
    untrusted = fixture_client_create(identity, other_ca_key, other_ca, uri, 1, 0);
    if (!valid || !wrong_key || !wrong_san || !no_eku || !client_ca || !untrusted)
        goto done;
#define FIXTURE_PATH_WRITE(name_, data_, length_) \
    do { \
        if (fixture_path(path, sizeof(path), (name_)) != 0 || \
            fixture_write(path, (const unsigned char *)(data_), (length_)) != 0) \
            goto done; \
    } while (0)
    FIXTURE_PATH_WRITE("identity.ed25519", private_key, sizeof(private_key));
    FIXTURE_PATH_WRITE("bootstrap.json", bootstrap, sizeof(bootstrap) - 1);
#undef FIXTURE_PATH_WRITE
    if (fixture_path(path, sizeof(path), "controller-ca.pem") != 0 ||
        fixture_x509_pem_write(path, ca) != 0)
        goto done;
    if (fixture_path(path, sizeof(path), "input-nonca.pem") != 0 ||
        fixture_x509_pem_write(path, valid) != 0)
        goto done;
#define FIXTURE_CERT(name_, cert_) \
    do { \
        if (fixture_path(path, sizeof(path), (name_)) != 0 || \
            fixture_x509_der_write(path, (cert_)) != 0) \
            goto done; \
    } while (0)
    FIXTURE_CERT("input-valid.der", valid);
    FIXTURE_CERT("input-wrong-key.der", wrong_key);
    FIXTURE_CERT("input-wrong-san.der", wrong_san);
    FIXTURE_CERT("input-no-eku.der", no_eku);
    FIXTURE_CERT("input-client-ca.der", client_ca);
    FIXTURE_CERT("input-untrusted.der", untrusted);
#undef FIXTURE_CERT
    rc = 0;
done:
    X509_free(untrusted);
    X509_free(client_ca);
    X509_free(no_eku);
    X509_free(wrong_san);
    X509_free(wrong_key);
    X509_free(valid);
    X509_free(other_ca);
    X509_free(ca);
    EVP_PKEY_free(other_ca_key);
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(wrong_identity);
    EVP_PKEY_free(identity);
    OPENSSL_cleanse(private_key, sizeof(private_key));
    return rc;
}

static void fixture_metadata_print(const struct apd_enrollment_metadata *metadata)
{
    printf("controller_id=%s\n", metadata->controller_id);
    printf("controller_host=%s\n", metadata->controller_host);
    printf("controller_port=%u\n", metadata->controller_port);
    printf("enrollment_id=%s\n", metadata->enrollment_id);
    printf("certificate_id=%s\n", metadata->certificate_id);
    printf("ap_id=%s\n", metadata->ap_id);
    printf("serial=%s\n", metadata->serial);
    printf("not_before=%lld\n", (long long)metadata->not_before);
    printf("not_after=%lld\n", (long long)metadata->not_after);
    printf("certificate_fingerprint=%s\n", metadata->certificate_fingerprint);
    printf("ca_fingerprint=%s\n", metadata->ca_fingerprint);
    printf("state=%s\n", metadata->state);
}

static int fixture_bootstrap(void)
{
    struct apd_bootstrap_config config;
    int rc;

    memset(&config, 0, sizeof(config));
    rc = apd_credentials_bootstrap_load(&config);
    if (rc == 0) {
        printf("version=%d\n", config.version);
        printf("controller_host=%s\n", config.controller_host);
        printf("controller_port=%u\n", config.controller_port);
        printf("controller_id_present=%d\n", config.controller_id_present);
        printf("controller_id=%s\n", config.controller_id);
        printf("token_id=%s\n", config.token_id);
        printf("site_id=%s\n", config.site_id);
        printf("hardware_digest=%s\n", config.hardware_digest);
        printf("ca_cert_pem_path=%s\n", config.ca_cert_pem_path);
    }
    apd_credentials_bootstrap_cleanse(&config);
    return rc;
}

static int fixture_der_read(const char *name, unsigned char **out,
                            size_t *out_len)
{
    char path[PATH_MAX];

    return fixture_path(path, sizeof(path), name) == 0 ?
        apd_credentials_read_binary_secure(path, APD_CREDENTIALS_CERT_MAX,
                                           out, out_len) : -1;
}

static int fixture_store(const char *name)
{
    struct apd_credentials_certificate_input input;
    struct apd_enrollment_metadata metadata;
    unsigned char *der = NULL;
    size_t der_len = 0;
    int rc;

    memset(&input, 0, sizeof(input));
    memset(&metadata, 0, sizeof(metadata));
    if (fixture_der_read(name, &der, &der_len) != 0)
        return -1;
    input.certificate_der = der;
    input.certificate_der_len = der_len;
    apd_credentials_copy(input.controller_id, sizeof(input.controller_id),
                         fixture_controller_id);
    apd_credentials_copy(input.enrollment_id, sizeof(input.enrollment_id),
                         fixture_enrollment_id);
    apd_credentials_copy(input.certificate_id, sizeof(input.certificate_id),
                         fixture_certificate_id);
    rc = apd_credentials_certificate_store(&input, &metadata);
    if (rc == 0)
        fixture_metadata_print(&metadata);
    apd_credentials_metadata_cleanse(&metadata);
    OPENSSL_cleanse(der, der_len);
    free(der);
    return rc;
}

static int fixture_validate(void)
{
    struct apd_enrollment_metadata metadata;
    int rc;

    memset(&metadata, 0, sizeof(metadata));
    rc = apd_credentials_validate_startup(&metadata);
    if (rc == 0)
        fixture_metadata_print(&metadata);
    apd_credentials_metadata_cleanse(&metadata);
    return rc;
}

static int fixture_activate(int wrong_fingerprint, int alias_input_output)
{
    struct apd_enrollment_metadata metadata;
    unsigned char fingerprint[SHA256_DIGEST_LENGTH];
    char path[PATH_MAX];
    unsigned char *der = NULL;
    size_t der_len = 0;
    int rc;

    memset(&metadata, 0, sizeof(metadata));
    memset(fingerprint, 0, sizeof(fingerprint));
    if (fixture_path(path, sizeof(path), APD_CREDENTIALS_CERT_FILE) != 0 ||
        apd_credentials_read_binary_secure(path, APD_CREDENTIALS_CERT_MAX,
                                           &der, &der_len) != 0 ||
        !SHA256(der, der_len, fingerprint))
        return -1;
    if (wrong_fingerprint)
        fingerprint[0] ^= 0xff;
    if (alias_input_output &&
        apd_credentials_validate_startup(&metadata) != 0)
        rc = -1;
    else if (alias_input_output)
        rc = apd_credentials_activate(metadata.controller_id,
                                      metadata.enrollment_id,
                                      metadata.certificate_id, fingerprint,
                                      &metadata);
    else
        rc = apd_credentials_activate(fixture_controller_id,
                                      fixture_enrollment_id,
                                      fixture_certificate_id, fingerprint,
                                      &metadata);
    if (rc == 0)
        fixture_metadata_print(&metadata);
    apd_credentials_metadata_cleanse(&metadata);
    OPENSSL_cleanse(fingerprint, sizeof(fingerprint));
    OPENSSL_cleanse(der, der_len);
    free(der);
    return rc;
}

int main(int argc, char **argv)
{
    const char *command = argc > 1 ? argv[1] : "";
    int rc = -1;

    if (strcmp(command, "setup") == 0)
        rc = fixture_setup();
    else if (strcmp(command, "bootstrap") == 0)
        rc = fixture_bootstrap();
    else if (strcmp(command, "store") == 0 && argc == 3)
        rc = fixture_store(argv[2]);
    else if (strcmp(command, "validate") == 0)
        rc = fixture_validate();
    else if (strcmp(command, "activate") == 0)
        rc = fixture_activate(0, 0);
    else if (strcmp(command, "activate-alias") == 0)
        rc = fixture_activate(0, 1);
    else if (strcmp(command, "activate-wrong") == 0)
        rc = fixture_activate(1, 0);
    return rc == 0 ? 0 : 1;
}
