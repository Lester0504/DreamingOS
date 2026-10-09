// SPDX-License-Identifier: GPL-2.0-or-later
/* Exercise the actual cert agent without UCI changes, DNS or CA requests. */
#include "cloud_internal.h"
#include <assert.h>
#include <stdatomic.h>

static int fail_sync;
static int failed_fd = -1;

static int fixture_fsync(int fd)
{
    if (fail_sync) {
        failed_fd = fd;
        errno = EIO;
        return -1;
    }
    return fsync(fd);
}

#define fsync fixture_fsync
#include "../src/cloud/cloud_cert.c"
#undef fsync

static atomic_int reload_done;
static int reload_failures;
static int reload_echild;

static void *fixture_reload_thread(void *unused)
{
    (void)unused;
    for (int i = 0; i < 1000; i++) {
        if (cloud_cert_reload("true") != 0) {
            reload_failures++;
            if (errno == ECHILD)
                reload_echild++;
        }
    }
    atomic_store(&reload_done, 1);
    return NULL;
}

static int fixture_reload_probe(int handle_sigchld)
{
    pthread_t thread;

    uloop_handle_sigchld = handle_sigchld;
    assert(uloop_init() == 0);
    assert(pthread_create(&thread, NULL, fixture_reload_thread, NULL) == 0);
    while (!atomic_load(&reload_done))
        uloop_run_timeout(1);
    assert(pthread_join(thread, NULL) == 0);
    uloop_done();
    printf("reload_probe sigchld=%d attempts=1000 failures=%d ECHILD=%d\n",
           handle_sigchld, reload_failures, reload_echild);
    return reload_failures ? 1 : 0;
}

static char *fixture_certificate(EVP_PKEY *key, long before, long after)
{
    X509 *cert = X509_new();
    X509_NAME *name;
    BIO *bio = BIO_new(BIO_s_mem());
    char *data;
    char *pem;
    long length;

    assert(cert && bio);
    assert(X509_set_version(cert, 2) == 1);
    assert(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) == 1);
    assert(X509_gmtime_adj(X509_getm_notBefore(cert), before));
    assert(X509_gmtime_adj(X509_getm_notAfter(cert), after));
    assert(X509_set_pubkey(cert, key) == 1);
    name = X509_get_subject_name(cert);
    assert(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char *)"fixture.dev.example.com", -1, -1, 0) == 1);
    assert(X509_set_issuer_name(cert, name) == 1);
    assert(X509_sign(cert, key, EVP_sha256()) > 0);
    assert(PEM_write_bio_X509(bio, cert) == 1);
    length = BIO_get_mem_data(bio, &data);
    assert(length > 0);
    pem = strndup(data, (size_t)length);
    assert(pem);
    BIO_free(bio);
    X509_free(cert);
    return pem;
}

int main(void)
{
    char directory[] = "/tmp/cert-fixture-XXXXXX";
    struct cloud_cert_config config = {0};
    EVP_PKEY *key = NULL;
    EVP_PKEY *public_key;
    X509_REQ *request;
    STACK_OF(X509_EXTENSION) *extensions;
    GENERAL_NAMES *names;
    unsigned char *der = NULL;
    unsigned char *key_pem = NULL;
    const unsigned char *cursor;
    size_t der_len = 0;
    size_t key_len = 0;
    struct stat st;
    char *chain;
    char path[512];
    char hash[65];
    unsigned char contents[8] = {0};
    int fd;

    if (getenv("C6_PROBE_SIGCHLD"))
        return fixture_reload_probe(atoi(getenv("C6_PROBE_SIGCHLD")));
    assert(mkdtemp(directory));
    snprintf(config.key_path, sizeof(config.key_path), "%s/key.pem", directory);
    snprintf(config.fullchain_path, sizeof(config.fullchain_path), "%s/chain.pem", directory);
    assert(cloud_cert_generate_csr("fixture.dev.example.com", &key, &der,
                                  &der_len, &key_pem, &key_len) == 0);
    cursor = der;
    request = d2i_X509_REQ(NULL, &cursor, (long)der_len);
    assert(request && cursor == der + der_len);
    public_key = X509_REQ_get_pubkey(request);
    assert(public_key && EVP_PKEY_bits(public_key) == 256);
    assert(X509_REQ_verify(request, public_key) == 1);
    assert(EVP_PKEY_eq(key, public_key) == 1);
    extensions = X509_REQ_get_extensions(request);
    assert(extensions && sk_X509_EXTENSION_num(extensions) == 1);
    names = X509V3_EXT_d2i(sk_X509_EXTENSION_value(extensions, 0));
    assert(names && sk_GENERAL_NAME_num(names) == 1);
    assert(sk_GENERAL_NAME_value(names, 0)->type == GEN_DNS);
    assert(!strcmp((const char *)ASN1_STRING_get0_data(
        sk_GENERAL_NAME_value(names, 0)->d.dNSName), "fixture.dev.example.com"));
    assert(cloud_cert_hex_sha256((const unsigned char *)"abc", 3, hash, sizeof(hash)) == 0);
    assert(!strcmp(hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    puts("PASS csr_der_signature_p256_san_and_sha256");

    assert(cloud_cert_needs_renewal(&config) == 1);
    chain = fixture_certificate(key, -3600, 7200);
    assert(cloud_cert_install(&config, key_pem, key_len, chain) == 0);
    assert(stat(config.key_path, &st) == 0 && (st.st_mode & 0777) == 0600);
    assert(stat(config.fullchain_path, &st) == 0 && (st.st_mode & 0777) == 0644);
    assert(cloud_cert_needs_renewal(&config) == 0);
    snprintf(config.reload_cmd, sizeof(config.reload_cmd), "exit 7");
    assert(cloud_cert_install(&config, key_pem, key_len, chain) == -2);
    config.reload_cmd[0] = '\0';
    free(chain);
    chain = fixture_certificate(key, -7200, 900);
    assert(cloud_cert_install(&config, key_pem, key_len, chain) == 0);
    assert(cloud_cert_needs_renewal(&config) == 1);
    free(chain);
    puts("PASS atomic_install_modes_reload_failure_and_two_thirds_renewal");

    snprintf(path, sizeof(path), "%s/atomic", directory);
    assert(cloud_cert_write_atomic(path, (const unsigned char *)"old", 3, 0600) == 0);
    fail_sync = 1;
    assert(cloud_cert_write_atomic(path, (const unsigned char *)"new", 3, 0600) == -1);
    fail_sync = 0;
    assert(failed_fd >= 0 && fcntl(failed_fd, F_GETFD) == -1 && errno == EBADF);
    fd = open(path, O_RDONLY);
    assert(fd >= 0 && read(fd, contents, sizeof(contents)) == 3);
    close(fd);
    assert(!strcmp((const char *)contents, "old"));
    unlink(path);
    snprintf(path, sizeof(path), "%s/atomic.tmp", directory);
    assert(access(path, F_OK) == -1 && errno == ENOENT);
    puts("PASS fsync_failure_closes_fd_preserves_original_and_removes_temp");

    unlink(config.key_path);
    unlink(config.fullchain_path);
    assert(rmdir(directory) == 0);
    OPENSSL_clear_free(key_pem, key_len);
    free(der);
    EVP_PKEY_free(public_key);
    EVP_PKEY_free(key);
    GENERAL_NAMES_free(names);
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
    X509_REQ_free(request);
    return 0;
}
