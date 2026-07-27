// SPDX-License-Identifier: GPL-2.0-or-later
#define APD_TRANSPORT_TEST_STANDALONE
#define APD_TRANSPORT_HEARTBEAT_SECONDS 1
#define APD_TRANSPORT_BACKOFF_MIN_SECONDS 1
#define APD_TRANSPORT_BACKOFF_MAX_SECONDS 2
#include "../src/apd/apd_transport.c"

static struct apd_enrollment_metadata fixture_metadata;
static int fixture_metadata_present;
static int fixture_bootstrap_present = 1;
static int fixture_activation_attempts;
static const char *fixture_pki;
static const char *fixture_ca;
static const char *fixture_key;
static const char *fixture_csr;
static uint16_t fixture_port;
static int fixture_snapshot_calls;
static struct apd_radio_job_journal_entry fixture_radio_job;
static char fixture_radio_job_result[4096];
static int fixture_radio_job_present;
static int fixture_neighbor_scan_calls;
static int fixture_survey_scan_calls;

static int fixture_backend_snapshot(struct json_object **out)
{
    struct json_object *root = json_object_new_object();

    fixture_snapshot_calls++;
    if (fixture_snapshot_calls == 2) {
        json_object_put(root);
        *out = NULL;
        return -1;
    }
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string("ap-control.v1"));
    json_object_object_add(root, "snapshot_version",
                           json_object_new_string("wireless-snapshot.v1"));
    json_object_object_add(root, "source", json_object_new_string("dreamingwrt-apd"));
    json_object_object_add(root, "backend", json_object_new_string("fixture"));
    json_object_object_add(root, "observed_at", json_object_new_int64(apd_now_s()));
    json_object_object_add(root, "complete", json_object_new_boolean(1));
    json_object_object_add(root, "stale", json_object_new_boolean(0));
    json_object_object_add(root, "reason", json_object_new_null());
    json_object_object_add(root, "wireless_present", json_object_new_boolean(1));
    json_object_object_add(root, "phy_count", json_object_new_int(1));
    json_object_object_add(root, "radio_count", json_object_new_int(1));
    json_object_object_add(root, "ssid_count", json_object_new_int(1));
    json_object_object_add(root, "station_count", json_object_new_int(0));
    json_object_object_add(root, "model", json_object_new_string("Fixture AP 1"));
    json_object_object_add(root, "board_name", json_object_new_string("fixture,ap1"));
    json_object_object_add(root, "model_source",
                           json_object_new_string("ubus_system_board"));
    json_object_object_add(root, "model_available", json_object_new_boolean(1));
    json_object_object_add(root, "model_reason", json_object_new_string(""));
    json_object_object_add(root, "radios", json_tokener_parse(
        "[{\"id\":\"phy0\",\"band\":\"5GHz\",\"survey\":{"
        "\"source\":\"iw_survey\",\"sample_time\":1,\"complete\":true,"
        "\"channel_active_time_ms\":1000,\"channel_busy_time_ms\":200,"
        "\"utilization_pct\":20.0}}]"));
    json_object_object_add(root, "ssids", json_tokener_parse(
        "[{\"id\":\"wlan0\",\"radio_id\":\"phy0\",\"interface\":\"wlan0\",\"broadcast_name\":\"Fixture\"}]"));
    json_object_object_add(root, "stations", json_object_new_array());
    json_object_object_add(root, "desired", json_object_new_object());
    json_object_object_add(root, "sources", json_object_new_object());
    *out = root;
    return 0;
}

static const struct apd_backend_ops fixture_backend = {
    .name = "fixture",
    .snapshot_supported = 1,
    .snapshot = fixture_backend_snapshot,
};

const struct apd_backend_ops *apd_backend(void)
{
    return &fixture_backend;
}

int apd_backend_neighbor_scan(const char *radio_id, struct json_object **out)
{
    struct json_object *root;

    if (!radio_id || strcmp(radio_id, "phy0") != 0 || !out)
        return -1;
    fixture_neighbor_scan_calls++;
    root = json_object_new_object();
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "complete", json_object_new_boolean(1));
    json_object_object_add(root, "truncated", json_object_new_boolean(0));
    json_object_object_add(root, "error_code", json_object_new_string(""));
    json_object_object_add(root, "items", json_tokener_parse(
        "[{\"bssid\":\"02:00:00:00:00:01\",\"ssid\":\"Neighbor\","
        "\"rssi\":-47,\"frequency\":5180,\"channel\":36,"
        "\"width\":80,\"security\":\"wpa2\",\"standard\":\"802.11ac\"}]"));
    *out = root;
    return 0;
}

int apd_backend_survey_scan(const char *radio_id, struct json_object **out)
{
    struct json_object *root;

    if (!radio_id || strcmp(radio_id, "phy0") != 0 || !out)
        return -1;
    fixture_survey_scan_calls++;
    root = json_object_new_object();
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "complete", json_object_new_boolean(1));
    json_object_object_add(root, "truncated", json_object_new_boolean(0));
    json_object_object_add(root, "error_code", json_object_new_string(""));
    json_object_object_add(root, "items", json_tokener_parse(
        "[{\"radio_id\":\"phy0\",\"frequency\":5180,\"channel\":36,"
        "\"noise\":-95,\"busy_percent\":17}]"));
    *out = root;
    return 0;
}

int apd_radio_job_offer_store(const struct apd_radio_job_assignment *assignment,
                              int64_t now,
                              struct apd_radio_job_journal_entry *out)
{
    if (!assignment || now <= 0)
        return APD_RADIO_JOB_JOURNAL_INVALID;
    if (fixture_radio_job_present) {
        if (strcmp(fixture_radio_job.assignment.job_id, assignment->job_id) != 0)
            return APD_RADIO_JOB_JOURNAL_CONFLICT;
        if (out)
            *out = fixture_radio_job;
        return APD_RADIO_JOB_JOURNAL_IDEMPOTENT;
    }
    memset(&fixture_radio_job, 0, sizeof(fixture_radio_job));
    fixture_radio_job.assignment = *assignment;
    snprintf(fixture_radio_job.state, sizeof(fixture_radio_job.state), "%s",
             "offered");
    fixture_radio_job.created_at = now;
    fixture_radio_job.updated_at = now;
    fixture_radio_job_present = 1;
    if (out)
        *out = fixture_radio_job;
    return APD_RADIO_JOB_JOURNAL_OK;
}

int apd_radio_job_mark_running(const struct apd_radio_job_assignment *assignment,
                               int64_t now,
                               struct apd_radio_job_journal_entry *out)
{
    if (!fixture_radio_job_present || !assignment ||
        strcmp(fixture_radio_job.assignment.job_id, assignment->job_id) != 0 ||
        strcmp(fixture_radio_job.state, "offered") != 0)
        return APD_RADIO_JOB_JOURNAL_CONFLICT;
    snprintf(fixture_radio_job.state, sizeof(fixture_radio_job.state), "%s",
             "running");
    fixture_radio_job.updated_at = now;
    if (out)
        *out = fixture_radio_job;
    return APD_RADIO_JOB_JOURNAL_OK;
}

int apd_radio_job_cancel_requested(
    const struct apd_radio_job_assignment *assignment, int64_t now,
    struct apd_radio_job_journal_entry *out)
{
    if (!fixture_radio_job_present || !assignment ||
        strcmp(fixture_radio_job.assignment.job_id, assignment->job_id) != 0)
        return APD_RADIO_JOB_JOURNAL_CONFLICT;
    snprintf(fixture_radio_job.state, sizeof(fixture_radio_job.state), "%s",
             "cancel_requested");
    fixture_radio_job.updated_at = now;
    if (out)
        *out = fixture_radio_job;
    return APD_RADIO_JOB_JOURNAL_OK;
}

int apd_radio_job_finish_store(const struct apd_radio_job_finish *finish,
                               int64_t now,
                               struct apd_radio_job_journal_entry *out)
{
    struct json_object *items;

    if (!fixture_radio_job_present || !finish || !finish->result_json ||
        strcmp(fixture_radio_job.assignment.job_id,
               finish->assignment.job_id) != 0)
        return APD_RADIO_JOB_JOURNAL_CONFLICT;
    items = json_tokener_parse(finish->result_json);
    if (!items || !json_object_is_type(items, json_type_array)) {
        json_object_put(items);
        return APD_RADIO_JOB_JOURNAL_INVALID;
    }
    snprintf(fixture_radio_job_result, sizeof(fixture_radio_job_result), "%s",
             finish->result_json);
    snprintf(fixture_radio_job.state, sizeof(fixture_radio_job.state), "%s",
             finish->outcome);
    snprintf(fixture_radio_job.finish_id, sizeof(fixture_radio_job.finish_id),
             "%s", finish->finish_id);
    snprintf(fixture_radio_job.outcome, sizeof(fixture_radio_job.outcome), "%s",
             finish->outcome);
    snprintf(fixture_radio_job.error_code,
             sizeof(fixture_radio_job.error_code), "%s", finish->error_code);
    fixture_radio_job.observed_at = finish->observed_at;
    fixture_radio_job.result_complete = finish->result_complete;
    fixture_radio_job.result_count = (int)json_object_array_length(items);
    fixture_radio_job.result_bytes = (int64_t)strlen(finish->result_json);
    fixture_radio_job.updated_at = now;
    json_object_put(items);
    if (out)
        *out = fixture_radio_job;
    return APD_RADIO_JOB_JOURNAL_OK;
}

int apd_radio_job_pending_reconcile_get(
    const char *ap_id, struct apd_radio_job_pending_reconcile *out)
{
    if (!out || !ap_id)
        return APD_RADIO_JOB_JOURNAL_INVALID;
    memset(out, 0, sizeof(*out));
    if (!fixture_radio_job_present || fixture_radio_job.finish_acked ||
        strcmp(fixture_radio_job.assignment.ap_id, ap_id) != 0)
        return APD_RADIO_JOB_JOURNAL_NOT_FOUND;
    out->entry = fixture_radio_job;
    out->result_json = strdup(fixture_radio_job_result[0] ?
                              fixture_radio_job_result : "[]");
    return out->result_json ? APD_RADIO_JOB_JOURNAL_OK
                            : APD_RADIO_JOB_JOURNAL_ERROR;
}

int apd_radio_job_pending_finish_get(
    const char *ap_id, struct apd_radio_job_pending_finish *out)
{
    if (!out || !ap_id)
        return APD_RADIO_JOB_JOURNAL_INVALID;
    memset(out, 0, sizeof(*out));
    if (!fixture_radio_job_present || fixture_radio_job.finish_acked ||
        !fixture_radio_job.finish_id[0] ||
        strcmp(fixture_radio_job.assignment.ap_id, ap_id) != 0)
        return APD_RADIO_JOB_JOURNAL_NOT_FOUND;
    out->entry = fixture_radio_job;
    out->result_json = strdup(fixture_radio_job_result[0] ?
                              fixture_radio_job_result : "[]");
    return out->result_json ? APD_RADIO_JOB_JOURNAL_OK
                            : APD_RADIO_JOB_JOURNAL_ERROR;
}

void apd_radio_job_pending_finish_free(
    struct apd_radio_job_pending_finish *pending)
{
    if (!pending)
        return;
    free(pending->result_json);
    memset(pending, 0, sizeof(*pending));
}

void apd_radio_job_pending_reconcile_free(
    struct apd_radio_job_pending_reconcile *pending)
{
    if (pending)
        free(pending->result_json);
    if (pending)
        memset(pending, 0, sizeof(*pending));
}

int apd_radio_job_session_rebind(
    const struct apd_radio_job_assignment *old_assignment,
    const char *new_session_epoch, int64_t now,
    struct apd_radio_job_journal_entry *out)
{
    if (!fixture_radio_job_present || !old_assignment || !new_session_epoch ||
        strlen(new_session_epoch) != 64 || now <= 0 ||
        strcmp(fixture_radio_job.assignment.job_id,
               old_assignment->job_id) != 0)
        return APD_RADIO_JOB_JOURNAL_CONFLICT;
    snprintf(fixture_radio_job.assignment.session_epoch,
             sizeof(fixture_radio_job.assignment.session_epoch), "%s",
             new_session_epoch);
    fixture_radio_job.updated_at = now;
    if (out)
        *out = fixture_radio_job;
    return APD_RADIO_JOB_JOURNAL_OK;
}

int apd_radio_job_finish_ack(const struct apd_radio_job_assignment *assignment,
                             const char *finish_id, int64_t now,
                             struct apd_radio_job_journal_entry *out)
{
    if (!fixture_radio_job_present || !assignment || !finish_id || now <= 0 ||
        strcmp(fixture_radio_job.assignment.job_id, assignment->job_id) != 0 ||
        strcmp(fixture_radio_job.finish_id, finish_id) != 0)
        return APD_RADIO_JOB_JOURNAL_CONFLICT;
    if (fixture_radio_job.finish_acked)
        return APD_RADIO_JOB_JOURNAL_IDEMPOTENT;
    fixture_radio_job.finish_acked = 1;
    fixture_radio_job.updated_at = now;
    if (out)
        *out = fixture_radio_job;
    return APD_RADIO_JOB_JOURNAL_OK;
}

/* W2c config executor/journal symbols.  The config wire step is compiled
 * but apd_config_executor_enabled() is 0 in this build, so none of these
 * are ever called; they exist only so the dormant path links. */
int apd_config_candidate_validate(struct json_object *candidate,
                                  struct json_object **out)
{
    (void)candidate;
    if (out)
        *out = NULL;
    return -1;
}

int apd_config_stage(const struct apd_config_paths *paths,
                     struct json_object *candidate, struct json_object **out)
{
    (void)paths; (void)candidate;
    if (out)
        *out = NULL;
    return -1;
}

int apd_config_readback(const struct apd_config_paths *paths,
                        struct json_object *candidate,
                        struct json_object **out)
{
    (void)paths; (void)candidate;
    if (out)
        *out = NULL;
    return -1;
}

int apd_config_apply(const struct apd_config_paths *paths,
                     struct json_object *candidate, struct json_object **out)
{
    (void)paths; (void)candidate;
    if (out)
        *out = NULL;
    return -1;
}

int apd_config_rollback(const struct apd_config_paths *paths,
                        struct json_object *previous, struct json_object **out)
{
    (void)paths; (void)previous;
    if (out)
        *out = NULL;
    return -1;
}

int apd_config_job_journal_init(void)
{
    return APD_CONFIG_JOB_JOURNAL_OK;
}

int apd_config_job_offer_store(
    const struct apd_config_job_assignment *assignment,
    const char *candidate_json, int64_t now,
    struct apd_config_job_journal_entry *out)
{
    (void)assignment; (void)candidate_json; (void)now; (void)out;
    return APD_CONFIG_JOB_JOURNAL_ERROR;
}

int apd_config_job_mark_staged(
    const struct apd_config_job_assignment *assignment, int64_t now,
    struct apd_config_job_journal_entry *out)
{
    (void)assignment; (void)now; (void)out;
    return APD_CONFIG_JOB_JOURNAL_ERROR;
}

int apd_config_job_mark_applying(
    const struct apd_config_job_assignment *assignment,
    const char *previous_json, int64_t now,
    struct apd_config_job_journal_entry *out)
{
    (void)assignment; (void)previous_json; (void)now; (void)out;
    return APD_CONFIG_JOB_JOURNAL_ERROR;
}

int apd_config_job_mark_applied(
    const struct apd_config_job_assignment *assignment, int64_t now,
    struct apd_config_job_journal_entry *out)
{
    (void)assignment; (void)now; (void)out;
    return APD_CONFIG_JOB_JOURNAL_ERROR;
}

int apd_config_job_finish_store(const struct apd_config_job_finish *finish,
                                int64_t now,
                                struct apd_config_job_journal_entry *out)
{
    (void)finish; (void)now; (void)out;
    return APD_CONFIG_JOB_JOURNAL_ERROR;
}

int apd_config_job_finish_ack(
    const struct apd_config_job_assignment *assignment,
    const char *finish_id, int64_t now,
    struct apd_config_job_journal_entry *out)
{
    (void)assignment; (void)finish_id; (void)now; (void)out;
    return APD_CONFIG_JOB_JOURNAL_ERROR;
}

int apd_backend_device_model_collect(struct apd_device_model *out)
{
    memset(out, 0, sizeof(*out));
    snprintf(out->model, sizeof(out->model), "%s", "Fixture AP 1");
    snprintf(out->board_name, sizeof(out->board_name), "%s", "fixture,ap1");
    snprintf(out->model_source, sizeof(out->model_source), "%s",
             "ubus_system_board");
    out->model_available = 1;
    return 0;
}

static int fixture_read(const char *path, unsigned char *out, size_t capacity,
                        size_t *out_length)
{
    struct stat status;
    size_t offset = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0 || fstat(fd, &status) != 0 || status.st_size <= 0 ||
        (uint64_t)status.st_size > capacity)
        goto fail;
    while (offset < (size_t)status.st_size) {
        ssize_t count = read(fd, out + offset, (size_t)status.st_size - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            goto fail;
        offset += (size_t)count;
    }
    close(fd);
    *out_length = offset;
    return 0;
fail:
    if (fd >= 0)
        close(fd);
    return -1;
}

static EVP_PKEY *fixture_key_open(void)
{
    FILE *file = fopen(fixture_key, "r");
    EVP_PKEY *key = NULL;

    if (file) {
        key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
        fclose(file);
    }
    return key;
}

int64_t apd_now_s(void)
{
    return (int64_t)time(NULL);
}

int apd_db_identity_get(struct apd_node_identity *out)
{
    EVP_PKEY *key = fixture_key_open();
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char encoded[SHA256_DIGEST_LENGTH * 2 + 1];
    size_t length = sizeof(out->public_key);
    int rc = -1;

    if (!out || !key)
        goto done;
    memset(out, 0, sizeof(*out));
    if (EVP_PKEY_get_raw_public_key(key, out->public_key, &length) <= 0 ||
        length != sizeof(out->public_key) ||
        !SHA256(out->public_key, sizeof(out->public_key), digest) ||
        ap_control_hex_encode(digest, sizeof(digest), encoded,
                              sizeof(encoded)) != AP_CONTROL_WIRE_OK)
        goto done;
    snprintf(out->ap_id, sizeof(out->ap_id), "%s",
             "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    snprintf(out->key_id, sizeof(out->key_id), "sha256:%s", encoded);
    rc = 0;
done:
    EVP_PKEY_free(key);
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(encoded, sizeof(encoded));
    return rc;
}

EVP_PKEY *apd_identity_key_open(void)
{
    return fixture_key_open();
}

int apd_db_pairing_status_get(struct apd_pairing_status *out)
{
    memset(out, 0, sizeof(*out));
    snprintf(out->state, sizeof(out->state), "%s", "unpaired");
    return 0;
}

int apd_db_pairing_begin(const char *controller_id, const char *request_id,
                         int64_t expires_at)
{
    return controller_id && request_id && expires_at > apd_now_s() ? 0 : -1;
}

int apd_db_pairing_set_challenge(const char *request_id,
                                 const unsigned char *challenge,
                                 size_t challenge_len)
{
    return request_id && challenge && challenge_len == 32 ? 0 : -1;
}

int apd_db_pairing_verify_challenge(const char *request_id,
                                    const unsigned char *challenge,
                                    size_t challenge_len)
{
    return request_id && challenge && challenge_len == 32 ? 0 : -1;
}

int apd_db_pairing_reset(const char *request_id)
{
    return request_id ? 0 : -1;
}

int apd_enrollment_csr_create(unsigned char *csr_der, size_t csr_der_size,
                              size_t *csr_der_len,
                              unsigned char csr_sha256[SHA256_DIGEST_LENGTH])
{
    if (fixture_read(fixture_csr, csr_der, csr_der_size, csr_der_len) != 0 ||
        !SHA256(csr_der, *csr_der_len, csr_sha256))
        return -1;
    return 0;
}

int apd_enrollment_transcript_sign_v1(
    const struct apd_enrollment_transcript_v1 *input,
    unsigned char signature[APD_ED25519_SIGNATURE_LEN])
{
    EVP_PKEY *key = fixture_key_open();
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned char digest[SHA256_DIGEST_LENGTH];
    size_t length = APD_ED25519_SIGNATURE_LEN;
    int rc = -1;

    if (!input || !key || !context ||
        !SHA256(input->csr_sha256, sizeof(input->csr_sha256), digest) ||
        EVP_DigestSignInit(context, NULL, NULL, NULL, key) <= 0 ||
        EVP_DigestSign(context, signature, &length, digest, sizeof(digest)) <= 0 ||
        length != APD_ED25519_SIGNATURE_LEN)
        goto done;
    rc = 0;
done:
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(digest, sizeof(digest));
    return rc;
}

const char *apd_credentials_pki_dir(void)
{
    return fixture_pki;
}

int apd_credentials_bootstrap_load(struct apd_bootstrap_config *out)
{
    if (!out || !fixture_bootstrap_present)
        return -1;
    memset(out, 0, sizeof(*out));
    out->version = 1;
    snprintf(out->controller_host, sizeof(out->controller_host), "%s",
             "127.0.0.1");
    out->controller_port = fixture_port;
    out->controller_id_present = 1;
    snprintf(out->controller_id, sizeof(out->controller_id), "%s",
             "bbbbbbbb-bbbb-5bbb-8bbb-bbbbbbbbbbbb");
    snprintf(out->token_id, sizeof(out->token_id), "%s",
             "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
    snprintf(out->token, sizeof(out->token), "%s",
             "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    snprintf(out->site_id, sizeof(out->site_id), "%s", "default");
    snprintf(out->ca_cert_pem_path, sizeof(out->ca_cert_pem_path), "%s",
             fixture_ca);
    return 0;
}

int apd_credentials_certificate_store(
    const struct apd_credentials_certificate_input *input,
    struct apd_enrollment_metadata *out)
{
    char path[PATH_MAX];
    unsigned char fingerprint[SHA256_DIGEST_LENGTH];
    char encoded[SHA256_DIGEST_LENGTH * 2 + 1];
    int fd;
    size_t offset = 0;

    if (!input || !input->certificate_der ||
        snprintf(path, sizeof(path), "%s/client-cert.der", fixture_pki) >=
            (int)sizeof(path) ||
        (fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600)) < 0 ||
        fchmod(fd, 0600) != 0)
        return -1;
    while (offset < input->certificate_der_len) {
        ssize_t count = write(fd, input->certificate_der + offset,
                              input->certificate_der_len - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            close(fd);
            return -1;
        }
        offset += (size_t)count;
    }
    if (close(fd) != 0 ||
        !SHA256(input->certificate_der, input->certificate_der_len,
                fingerprint) ||
        ap_control_hex_encode(fingerprint, sizeof(fingerprint), encoded,
                              sizeof(encoded)) != AP_CONTROL_WIRE_OK)
        return -1;
    memset(&fixture_metadata, 0, sizeof(fixture_metadata));
    fixture_metadata.version = 1;
    snprintf(fixture_metadata.controller_id,
             sizeof(fixture_metadata.controller_id), "%s",
             input->controller_id);
    snprintf(fixture_metadata.enrollment_id,
             sizeof(fixture_metadata.enrollment_id), "%s",
             input->enrollment_id);
    snprintf(fixture_metadata.certificate_id,
             sizeof(fixture_metadata.certificate_id), "%s",
             input->certificate_id);
    snprintf(fixture_metadata.ap_id, sizeof(fixture_metadata.ap_id), "%s",
             "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    snprintf(fixture_metadata.certificate_fingerprint,
             sizeof(fixture_metadata.certificate_fingerprint),
             "sha256:%s", encoded);
    snprintf(fixture_metadata.ca_cert_pem_path,
             sizeof(fixture_metadata.ca_cert_pem_path), "%s", fixture_ca);
    snprintf(fixture_metadata.controller_host,
             sizeof(fixture_metadata.controller_host), "%s", "127.0.0.1");
    fixture_metadata.controller_port = fixture_port;
    snprintf(fixture_metadata.state, sizeof(fixture_metadata.state), "%s",
             "mtls_pending");
    fixture_metadata_present = 1;
    if (out)
        *out = fixture_metadata;
    OPENSSL_cleanse(fingerprint, sizeof(fingerprint));
    OPENSSL_cleanse(encoded, sizeof(encoded));
    return 0;
}

int apd_credentials_validate_startup(struct apd_enrollment_metadata *out)
{
    if (!fixture_metadata_present)
        return -1;
    if (out)
        *out = fixture_metadata;
    return 0;
}

int apd_credentials_activate(
    const char *controller_id, const char *enrollment_id,
    const char *certificate_id,
    const unsigned char fingerprint[SHA256_DIGEST_LENGTH],
    struct apd_enrollment_metadata *out)
{
    (void)fingerprint;
    if (!fixture_metadata_present ||
        strcmp(controller_id, fixture_metadata.controller_id) != 0 ||
        strcmp(enrollment_id, fixture_metadata.enrollment_id) != 0 ||
        strcmp(certificate_id, fixture_metadata.certificate_id) != 0)
        return -1;
    fixture_activation_attempts++;
    fixture_bootstrap_present = 0;
    pthread_mutex_lock(&g_apd_transport.lock);
    memset(&g_apd_transport.endpoint, 0, sizeof(g_apd_transport.endpoint));
    pthread_mutex_unlock(&g_apd_transport.lock);
    if (fixture_activation_attempts == 1)
        return -1;
    snprintf(fixture_metadata.state, sizeof(fixture_metadata.state), "%s",
             "adopted");
    if (out)
        *out = fixture_metadata;
    return 0;
}

void apd_credentials_bootstrap_cleanse(struct apd_bootstrap_config *config)
{
    OPENSSL_cleanse(config, sizeof(*config));
}

void apd_credentials_metadata_cleanse(struct apd_enrollment_metadata *metadata)
{
    OPENSSL_cleanse(metadata, sizeof(*metadata));
}

static int fixture_set_survey_counters(struct json_object *snapshot,
                                       int64_t sample_time,
                                       int64_t active_time,
                                       int64_t busy_time)
{
    struct json_object *radios = NULL;
    struct json_object *radio;
    struct json_object *survey = NULL;

    if (!snapshot ||
        !json_object_object_get_ex(snapshot, "radios", &radios) ||
        !json_object_is_type(radios, json_type_array) ||
        json_object_array_length(radios) != 1 ||
        !(radio = json_object_array_get_idx(radios, 0)) ||
        !json_object_object_get_ex(radio, "survey", &survey) ||
        !json_object_is_type(survey, json_type_object))
        return -1;
    json_object_object_add(survey, "sample_time",
                           json_object_new_int64(sample_time));
    json_object_object_add(survey, "channel_active_time_ms",
                           json_object_new_int64(active_time));
    json_object_object_add(survey, "channel_busy_time_ms",
                           json_object_new_int64(busy_time));
    json_object_object_add(survey, "utilization_pct", json_object_new_double(
        active_time > 0 ? (double)busy_time * 100.0 / (double)active_time : 0.0));
    return 0;
}

int main(int argc, char **argv)
{
    int connected_seen = 0;
    int adopted_seen = 0;
    int i;
    struct apd_telemetry_gate gate;
    struct json_object *base;
    struct json_object *volatile_only;
    struct json_object *survey_only;
    struct json_object *changed;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned char volatile_digest[SHA256_DIGEST_LENGTH];
    unsigned char survey_digest[SHA256_DIGEST_LENGTH];
    unsigned char changed_digest[SHA256_DIGEST_LENGTH];
    int telemetry_count = 0;
    int survey_suppressed = 0;

    if (argc != 6)
        return 2;
    memset(&gate, 0, sizeof(gate));
    base = json_tokener_parse(
        "{\"observed_at\":1,\"sources\":{\"iw\":{\"observed_at\":1}},"
        "\"radios\":[{\"id\":\"phy0\",\"survey\":{\"source\":\"iw_survey\","
        "\"sample_time\":1,\"complete\":true,\"channel_active_time_ms\":1000,"
        "\"channel_busy_time_ms\":200,\"utilization_pct\":20.0}}],"
        "\"ssids\":[{\"id\":\"wlan0\"}],"
        "\"stations\":[{\"mac\":\"02:00:00:00:00:01\",\"rx_bytes\":1}]}" );
    volatile_only = json_tokener_parse(
        "{\"observed_at\":99,\"sources\":{\"iw\":{\"observed_at\":99}},"
        "\"radios\":[{\"id\":\"phy0\",\"survey\":{\"source\":\"iw_survey\","
        "\"sample_time\":99,\"complete\":true,\"channel_active_time_ms\":99000,"
        "\"channel_busy_time_ms\":33000,\"utilization_pct\":33.333}}],"
        "\"ssids\":[{\"id\":\"wlan0\"}],"
        "\"stations\":[{\"mac\":\"02:00:00:00:00:01\",\"rx_bytes\":999}]}" );
    survey_only = json_tokener_parse(
        "{\"observed_at\":1,\"sources\":{\"iw\":{\"observed_at\":1}},"
        "\"radios\":[{\"id\":\"phy0\",\"survey\":{\"source\":\"other_driver\","
        "\"sample_time\":30,\"complete\":false,\"reason\":\"counter_pending\","
        "\"channel_active_time_ms\":2000,\"channel_busy_time_ms\":500,"
        "\"utilization_pct\":25.0,\"driver_extension\":{\"counter\":7}}}],"
        "\"ssids\":[{\"id\":\"wlan0\"}],"
        "\"stations\":[{\"mac\":\"02:00:00:00:00:01\",\"rx_bytes\":1}]}" );
    changed = json_tokener_parse(
        "{\"observed_at\":101,\"sources\":{\"iw\":{\"observed_at\":101}},"
        "\"radios\":[{\"id\":\"phy0\",\"survey\":{\"source\":\"iw_survey\","
        "\"sample_time\":101,\"complete\":true,\"channel_active_time_ms\":101000,"
        "\"channel_busy_time_ms\":20200,\"utilization_pct\":20.0}}],"
        "\"ssids\":[{\"id\":\"wlan1\"}],"
        "\"stations\":[{\"mac\":\"02:00:00:00:00:01\",\"rx_bytes\":999}]}" );
    if (!base || !volatile_only || !survey_only || !changed ||
        apd_telemetry_digest(base, digest) != 0 ||
        apd_telemetry_digest(volatile_only, volatile_digest) != 0 ||
        CRYPTO_memcmp(digest, volatile_digest, sizeof(digest)) != 0 ||
        apd_telemetry_digest(survey_only, survey_digest) != 0 ||
        CRYPTO_memcmp(digest, survey_digest, sizeof(digest)) != 0 ||
        apd_telemetry_digest(changed, changed_digest) != 0 ||
        CRYPTO_memcmp(digest, changed_digest, sizeof(digest)) == 0 ||
        !apd_telemetry_should_send(&gate, digest, 1, 0))
        return 6;
    memcpy(gate.digest, digest, sizeof(gate.digest));
    gate.digest_present = 1;
    gate.sent_at = 0;
    telemetry_count++;
    for (i = 1; i <= 3; i++) {
        if (fixture_set_survey_counters(survey_only, i * 30,
                                        1000 + i * 1000,
                                        200 + i * 250) != 0 ||
            apd_telemetry_digest(survey_only, survey_digest) != 0 ||
            CRYPTO_memcmp(digest, survey_digest, sizeof(digest)) != 0 ||
            apd_telemetry_should_send(&gate, survey_digest, 0, i * 30))
            return 7;
        survey_suppressed++;
    }
    if (telemetry_count != 1 ||
        !apd_telemetry_should_send(&gate, changed_digest, 0, 100))
        return 8;
    memcpy(gate.digest, changed_digest, sizeof(gate.digest));
    gate.sent_at = 100;
    telemetry_count++;
    for (i = 1; i <= 9; i++) {
        if (fixture_set_survey_counters(changed, 100 + i * 30,
                                        101000 + i * 1000,
                                        20200 + i * 250) != 0 ||
            apd_telemetry_digest(changed, survey_digest) != 0 ||
            CRYPTO_memcmp(changed_digest, survey_digest,
                          sizeof(changed_digest)) != 0 ||
            apd_telemetry_should_send(&gate, survey_digest, 0, 100 + i * 30))
            return 9;
        survey_suppressed++;
    }
    if (apd_telemetry_should_send(&gate, changed_digest, 0, 399) ||
        !apd_telemetry_should_send(&gate, changed_digest, 0, 400))
        return 10;
    telemetry_count++;
    json_object_put(base);
    json_object_put(volatile_only);
    json_object_put(survey_only);
    json_object_put(changed);
    fixture_pki = argv[1];
    fixture_ca = argv[2];
    fixture_key = argv[3];
    fixture_csr = argv[4];
    fixture_port = (uint16_t)strtoul(argv[5], NULL, 10);
    if (!fixture_port || apd_transport_start() != 0)
        return 3;
    for (i = 0; i < 200; i++) {
        connected_seen |= apd_transport_connected();
        adopted_seen |= apd_transport_adopted();
        if (connected_seen && adopted_seen &&
            strcmp(apd_transport_reason(), "session_ready") == 0)
            break;
        usleep(50000);
    }
    if (i == 200) {
        fprintf(stderr, "timeout reason=%s connected=%d adopted=%d activation_attempts=%d state=%s\n",
                apd_transport_reason(), apd_transport_connected(),
                apd_transport_adopted(), fixture_activation_attempts,
                fixture_metadata.state);
        apd_transport_stop();
        return 4;
    }
    sleep(3);
    apd_transport_stop();
    if (!connected_seen || !adopted_seen || !apd_transport_adopted() ||
        apd_transport_connected() ||
        fixture_activation_attempts != 2 ||
        fixture_neighbor_scan_calls != 1 || !fixture_radio_job.finish_acked ||
        strcmp(fixture_radio_job.state, "completed") != 0 ||
        fixture_radio_job.result_count != 1 ||
        strcmp(apd_transport_reason(), "stopped") != 0)
        return 5;
    printf("ok: APD TLS enrollment, activation, v2 radio job, heartbeat, telemetry, and state telemetry_gate=%d survey_30s_suppressed=%d forced_refresh_s=%d snapshot_calls=%d\n",
           telemetry_count, survey_suppressed, APD_TELEMETRY_REFRESH_SECONDS,
           fixture_snapshot_calls);
    return 0;
}
