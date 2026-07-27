// SPDX-License-Identifier: GPL-2.0-or-later
#include "ac_transport_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FIXTURE_AP_ID "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

static int telemetry_count;
static int identity_report_count;
static int64_t telemetry_sequence = -1;
static int64_t telemetry_observed_at;
static char telemetry_snapshot_id[72];
static int fixture_count_write(const char *name, int value);

#define FIXTURE_RADIO_JOB_COUNT 6

static struct ac_radio_job fixture_radio_jobs[FIXTURE_RADIO_JOB_COUNT];
static int fixture_radio_lease_index;
static int fixture_radio_lease_calls;
static int fixture_radio_start_calls;
static int fixture_radio_finish_calls;
static int fixture_radio_reconcile_calls;

static const char *const fixture_job_ids[FIXTURE_RADIO_JOB_COUNT] = {
    "10000000-0000-4000-8000-000000000001",
    "10000000-0000-4000-8000-000000000002",
    "10000000-0000-4000-8000-000000000003",
    "10000000-0000-4000-8000-000000000004",
    "10000000-0000-4000-8000-000000000005",
    "10000000-0000-4000-8000-000000000006",
};
static const char *const fixture_attempt_ids[FIXTURE_RADIO_JOB_COUNT] = {
    "20000000-0000-4000-8000-000000000001",
    "20000000-0000-4000-8000-000000000002",
    "20000000-0000-4000-8000-000000000003",
    "20000000-0000-4000-8000-000000000004",
    "20000000-0000-4000-8000-000000000005",
    "20000000-0000-4000-8000-000000000006",
};
static const char *const fixture_request_digests[FIXTURE_RADIO_JOB_COUNT] = {
    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    "sha256:4444444444444444444444444444444444444444444444444444444444444444",
    "sha256:5555555555555555555555555555555555555555555555555555555555555555",
    "sha256:6666666666666666666666666666666666666666666666666666666666666666",
};

static int fixture_radio_job_index(const char *job_id)
{
    int i;

    for (i = 0; i < FIXTURE_RADIO_JOB_COUNT; i++)
        if (job_id && !strcmp(job_id, fixture_job_ids[i]))
            return i;
    return -1;
}

static int fixture_radio_binding(const struct ac_radio_job *job,
                                 const char *attempt_id,
                                 int64_t dispatch_generation,
                                 const char *request_digest,
                                 const char *ap_id,
                                 const char *session_epoch)
{
    return job && attempt_id && request_digest && ap_id && session_epoch &&
        !strcmp(job->attempt_id, attempt_id) &&
        job->dispatch_generation == dispatch_generation &&
        !strcmp(job->request_digest, request_digest) &&
        !strcmp(job->ap_id, ap_id) &&
        !strcmp(job->session_epoch, session_epoch) &&
        !strcmp(session_epoch, fixture_current_session_epoch);
}

void fixture_radio_jobs_reset(const char *session_epoch)
{
    int i;

    memset(fixture_radio_jobs, 0, sizeof(fixture_radio_jobs));
    fixture_radio_lease_index = 0;
    fixture_radio_lease_calls = 0;
    fixture_radio_start_calls = 0;
    fixture_radio_finish_calls = 0;
    fixture_radio_reconcile_calls = 0;
    for (i = 0; i < FIXTURE_RADIO_JOB_COUNT; i++) {
        struct ac_radio_job *job = &fixture_radio_jobs[i];

        snprintf(job->job_id, sizeof(job->job_id), "%s", fixture_job_ids[i]);
        snprintf(job->ap_id, sizeof(job->ap_id), "%s", FIXTURE_AP_ID);
        snprintf(job->radio_id, sizeof(job->radio_id), "phy%d", i);
        snprintf(job->mode, sizeof(job->mode), "%s", "neighbor");
        snprintf(job->state, sizeof(job->state), "%s", "queued");
        snprintf(job->session_epoch, sizeof(job->session_epoch), "%s",
                 session_epoch);
        snprintf(job->attempt_id, sizeof(job->attempt_id), "%s",
                 fixture_attempt_ids[i]);
        job->dispatch_generation = i + 1;
        snprintf(job->request_digest, sizeof(job->request_digest), "%s",
                 fixture_request_digests[i]);
        snprintf(job->expected_impact, sizeof(job->expected_impact), "%s",
                 "brief_radio_scan");
    }
}

int ac_db_ap_session_is_current(const char *ap_id, const char *session_epoch)
{
    return ap_id && session_epoch && !strcmp(ap_id, FIXTURE_AP_ID) &&
        !strcmp(session_epoch, fixture_current_session_epoch);
}

int ac_db_radio_job_status(const char *job_id, struct ac_radio_job *out)
{
    int index = fixture_radio_job_index(job_id);

    if (index < 0 || !out)
        return AC_RADIO_JOB_NOT_FOUND;
    if ((index == 1 || index == 5) &&
        !strcmp(fixture_radio_jobs[index].state, "leased"))
        snprintf(fixture_radio_jobs[index].state,
                 sizeof(fixture_radio_jobs[index].state), "%s",
                 "cancel_requested");
    *out = fixture_radio_jobs[index];
    return AC_RADIO_JOB_OK;
}

int ac_db_radio_job_lease_next(const char *ap_id, const char *session_epoch,
                               int64_t now, struct ac_radio_job *out)
{
    struct ac_radio_job *job;

    if (!out || now <= 0 || !ac_db_ap_session_is_current(ap_id, session_epoch))
        return AC_RADIO_JOB_INVALID_TARGET;
    if (fixture_radio_lease_index >= FIXTURE_RADIO_JOB_COUNT)
        return AC_RADIO_JOB_NOT_FOUND;
    job = &fixture_radio_jobs[fixture_radio_lease_index++];
    snprintf(job->state, sizeof(job->state), "%s", "leased");
    snprintf(job->lease_owner, sizeof(job->lease_owner), "%s", ap_id);
    fixture_radio_lease_calls++;
    *out = *job;
    fixture_count_write("radio-lease-count", fixture_radio_lease_calls);
    return AC_RADIO_JOB_OK;
}

int ac_db_radio_job_mark_running(const char *job_id, const char *attempt_id,
                                 int64_t dispatch_generation,
                                 const char *request_digest, const char *ap_id,
                                 const char *session_epoch,
                                 struct ac_radio_job *out)
{
    int index = fixture_radio_job_index(job_id);
    struct ac_radio_job *job;

    if (index < 0 || !out)
        return AC_RADIO_JOB_CONFLICT;
    job = &fixture_radio_jobs[index];
    if (!fixture_radio_binding(job, attempt_id, dispatch_generation,
            request_digest, ap_id, session_epoch))
        return AC_RADIO_JOB_CONFLICT;
    if (!strcmp(job->state, "running")) {
        *out = *job;
        return AC_RADIO_JOB_IDEMPOTENT;
    }
    if (strcmp(job->state, "leased"))
        return AC_RADIO_JOB_CONFLICT;
    snprintf(job->state, sizeof(job->state), "%s", "running");
    fixture_radio_start_calls++;
    *out = *job;
    fixture_count_write("radio-start-count", fixture_radio_start_calls);
    return AC_RADIO_JOB_OK;
}

int ac_db_radio_job_finish(const char *job_id, const char *attempt_id,
                           int64_t dispatch_generation,
                           const char *request_digest, const char *ap_id,
                           const char *session_epoch, const char *finish_id,
                           const char *outcome, const char *error_code,
                           const char *result_json, int result_truncated,
                           struct ac_radio_job *out)
{
    int index = fixture_radio_job_index(job_id);
    struct ac_radio_job *job;
    struct json_object *result;

    if (index < 0 || !out || !finish_id || !result_json || !outcome ||
        !error_code)
        return AC_RADIO_JOB_CONFLICT;
    job = &fixture_radio_jobs[index];
    if (!fixture_radio_binding(job, attempt_id, dispatch_generation,
            request_digest, ap_id, session_epoch))
        return AC_RADIO_JOB_CONFLICT;
    if (job->finish_id[0]) {
        if (!strcmp(job->finish_id, finish_id)) {
            *out = *job;
            return AC_RADIO_JOB_IDEMPOTENT;
        }
        return AC_RADIO_JOB_CONFLICT;
    }
    result = json_tokener_parse(result_json);
    if ((strcmp(job->state, "running") &&
         strcmp(job->state, "cancel_requested") &&
         strcmp(job->state, outcome)) || !result ||
        !json_object_is_type(result, json_type_array) ||
        (!strcmp(outcome, "completed") ? error_code[0] != '\0' :
                                         error_code[0] == '\0') ||
        (strcmp(outcome, "completed") && strcmp(outcome, "failed") &&
         strcmp(outcome, "cancelled")) ||
        (!strcmp(outcome, "cancelled") && job->finish_id[0] == '\0' &&
         strcmp(job->state, "cancel_requested"))) {
        json_object_put(result);
        return AC_RADIO_JOB_CONFLICT;
    }
    job->result_count = (int)json_object_array_length(result);
    job->result_bytes = (int64_t)strlen(result_json);
    job->result_complete = (!strcmp(outcome, "completed") ||
                            !strcmp(outcome, "cancelled")) &&
                           !result_truncated;
    snprintf(job->finish_id, sizeof(job->finish_id), "%s", finish_id);
    snprintf(job->state, sizeof(job->state), "%s", outcome);
    snprintf(job->error_code, sizeof(job->error_code), "%s", error_code);
    fixture_radio_finish_calls++;
    *out = *job;
    fixture_count_write("radio-finish-count", fixture_radio_finish_calls);
    json_object_put(result);
    return AC_RADIO_JOB_OK;
}

/* One in-memory config job seeded queued; exercises the W2c wire without
 * any real store. */
static struct ac_config_job fixture_config_job = {
    .job_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    .state = "queued",
    .idempotency_key = "fixture.config.1",
    .candidate_digest = "sha256:cccccccccccccccccccccccccccccccc"
                        "cccccccccccccccccccccccccccccccc",
};
static const char fixture_config_candidate[] =
    "{\"format\":\"uci-wireless-candidate.v1\",\"sections\":[]}";
static int fixture_config_lease_calls;
static int fixture_config_start_calls;
static int fixture_config_finish_calls;

static int fixture_config_binding(const struct ac_config_job *job,
                                  const char *attempt_id,
                                  int64_t dispatch_generation,
                                  const char *request_digest,
                                  const char *ap_id,
                                  const char *session_epoch)
{
    return !strcmp(job->attempt_id, attempt_id) &&
           job->dispatch_generation == dispatch_generation &&
           !strcmp(job->request_digest, request_digest) &&
           !strcmp(job->ap_id, ap_id) &&
           !strcmp(job->session_epoch, session_epoch);
}

int ac_db_config_job_lease_next(const char *ap_id,
                                const char *session_epoch, int64_t now,
                                struct ac_config_job *out,
                                char **candidate_json_out)
{
    if (!out || !candidate_json_out || now <= 0 ||
        !ac_db_ap_session_is_current(ap_id, session_epoch))
        return AC_CONFIG_JOB_INVALID;
    *candidate_json_out = NULL;
    if (strcmp(fixture_config_job.state, "queued") != 0)
        return AC_CONFIG_JOB_NOT_FOUND;
    snprintf(fixture_config_job.ap_id, sizeof(fixture_config_job.ap_id),
             "%s", ap_id);
    snprintf(fixture_config_job.session_epoch,
             sizeof(fixture_config_job.session_epoch), "%s", session_epoch);
    snprintf(fixture_config_job.attempt_id,
             sizeof(fixture_config_job.attempt_id),
             "dddddddd-dddd-4ddd-8ddd-dddddddddddd");
    fixture_config_job.dispatch_generation = 1;
    snprintf(fixture_config_job.request_digest,
             sizeof(fixture_config_job.request_digest),
             "sha256:dddddddddddddddddddddddddddddddd"
             "dddddddddddddddddddddddddddddddd");
    snprintf(fixture_config_job.state, sizeof(fixture_config_job.state),
             "%s", "leased");
    *candidate_json_out = strdup(fixture_config_candidate);
    if (!*candidate_json_out)
        return AC_CONFIG_JOB_ERROR;
    fixture_config_lease_calls++;
    fixture_count_write("config-lease-count", fixture_config_lease_calls);
    *out = fixture_config_job;
    return AC_CONFIG_JOB_OK;
}

int ac_db_config_job_mark_running(const char *job_id, const char *attempt_id,
                                  int64_t dispatch_generation,
                                  const char *request_digest,
                                  const char *ap_id,
                                  const char *session_epoch, int64_t now,
                                  struct ac_config_job *out)
{
    if (!out || now <= 0 ||
        strcmp(job_id, fixture_config_job.job_id) != 0 ||
        !fixture_config_binding(&fixture_config_job, attempt_id,
                                dispatch_generation, request_digest, ap_id,
                                session_epoch))
        return AC_CONFIG_JOB_CONFLICT;
    if (!strcmp(fixture_config_job.state, "running")) {
        *out = fixture_config_job;
        return AC_CONFIG_JOB_IDEMPOTENT;
    }
    if (strcmp(fixture_config_job.state, "leased") != 0)
        return AC_CONFIG_JOB_CONFLICT;
    snprintf(fixture_config_job.state, sizeof(fixture_config_job.state),
             "%s", "running");
    fixture_config_start_calls++;
    fixture_count_write("config-start-count", fixture_config_start_calls);
    *out = fixture_config_job;
    return AC_CONFIG_JOB_OK;
}

int ac_db_config_job_finish(const char *job_id, const char *attempt_id,
                            int64_t dispatch_generation,
                            const char *request_digest, const char *ap_id,
                            const char *session_epoch,
                            const char *finish_id, const char *outcome,
                            const char *error_code,
                            const char *readback_json, int64_t now,
                            struct ac_config_job *out)
{
    if (!out || now <= 0 || !finish_id || !outcome || !error_code ||
        !readback_json ||
        strcmp(job_id, fixture_config_job.job_id) != 0 ||
        !fixture_config_binding(&fixture_config_job, attempt_id,
                                dispatch_generation, request_digest, ap_id,
                                session_epoch))
        return AC_CONFIG_JOB_CONFLICT;
    if (fixture_config_job.finish_id[0]) {
        if (!strcmp(fixture_config_job.finish_id, finish_id) &&
            !strcmp(fixture_config_job.outcome, outcome)) {
            *out = fixture_config_job;
            return AC_CONFIG_JOB_IDEMPOTENT;
        }
        return AC_CONFIG_JOB_CONFLICT;
    }
    if ((strcmp(fixture_config_job.state, "leased") &&
         strcmp(fixture_config_job.state, "running")) ||
        (strcmp(outcome, "applied") && strcmp(outcome, "failed") &&
         strcmp(outcome, "rolled_back")))
        return AC_CONFIG_JOB_CONFLICT;
    snprintf(fixture_config_job.finish_id,
             sizeof(fixture_config_job.finish_id), "%s", finish_id);
    snprintf(fixture_config_job.outcome,
             sizeof(fixture_config_job.outcome), "%s", outcome);
    snprintf(fixture_config_job.error_code,
             sizeof(fixture_config_job.error_code), "%s", error_code);
    snprintf(fixture_config_job.state, sizeof(fixture_config_job.state),
             "%s", outcome);
    fixture_config_finish_calls++;
    fixture_count_write("config-finish-count", fixture_config_finish_calls);
    *out = fixture_config_job;
    return AC_CONFIG_JOB_OK;
}

int ac_db_radio_job_reconcile(const char *job_id, const char *attempt_id,
                              int64_t dispatch_generation,
                              const char *request_digest, const char *ap_id,
                              const char *session_epoch,
                              const char *reported_state, int64_t now,
                              struct ac_radio_job *out)
{
    int index = fixture_radio_job_index(job_id);
    struct ac_radio_job *job;

    if (index < 0 || !out || !reported_state || now <= 0)
        return AC_RADIO_JOB_CONFLICT;
    job = &fixture_radio_jobs[index];
    if (!fixture_radio_binding(job, attempt_id, dispatch_generation,
            request_digest, ap_id, session_epoch))
        return AC_RADIO_JOB_CONFLICT;
    if (!strcmp(reported_state, "leased")) {
        if (strcmp(job->state, "leased"))
            return AC_RADIO_JOB_CONFLICT;
    } else if (!strcmp(reported_state, "running")) {
        if (strcmp(job->state, "running") &&
            strcmp(job->state, "cancel_requested"))
            return AC_RADIO_JOB_CONFLICT;
    } else if (!strcmp(reported_state, "cancelled")) {
        if (strcmp(job->state, "cancel_requested"))
            return AC_RADIO_JOB_CONFLICT;
        snprintf(job->state, sizeof(job->state), "%s", "cancelled");
        snprintf(job->error_code, sizeof(job->error_code), "%s",
                 "cancelled_by_apd");
    } else if (!strcmp(reported_state, "interrupted")) {
        if (strcmp(job->state, "leased") && strcmp(job->state, "running"))
            return AC_RADIO_JOB_CONFLICT;
        snprintf(job->state, sizeof(job->state), "%s", "failed");
        snprintf(job->error_code, sizeof(job->error_code), "%s",
                 "apd_restarted_during_execution");
    } else {
        return AC_RADIO_JOB_CONFLICT;
    }
    fixture_radio_reconcile_calls++;
    *out = *job;
    fixture_count_write("radio-reconcile-count", fixture_radio_reconcile_calls);
    return AC_RADIO_JOB_OK;
}

static int fixture_count_write(const char *name, int value)
{
    const char *directory = getenv("AC_TRANSPORT_TEST_OUTPUT");
    char path[1024];
    FILE *file;

    if (!directory || !directory[0] || !name ||
        snprintf(path, sizeof(path), "%s/%s", directory, name) >=
            (int)sizeof(path) || !(file = fopen(path, "w")))
        return -1;
    if (fprintf(file, "%d\n", value) < 0 || fclose(file) != 0)
        return -1;
    return 0;
}

int ac_db_ap_identity_report(const char *ap_id,
                             const struct ac_device_model_report *report)
{
    if (!ap_id || strcmp(ap_id, FIXTURE_AP_ID) != 0 || !report ||
        strcmp(report->model, "Fixture AP 1") != 0 ||
        strcmp(report->board_name, "fixture,ap1") != 0 ||
        strcmp(report->model_source, "ubus_system_board") != 0 ||
        !report->model_available || report->reason[0])
        return -1;
    identity_report_count++;
    return fixture_count_write("identity-report-count", identity_report_count);
}

int ac_db_ap_telemetry_store(const char *ap_id, const char *session_epoch,
                             int64_t sequence,
                             int64_t observed_at, int64_t received_at,
                             const char *snapshot_id,
                             const struct ac_device_model_report *report,
                             struct json_object *snapshot)
{
    struct json_object *radios = NULL;
    struct json_object *ssids = NULL;
    struct json_object *stations = NULL;

    if (!ap_id || strcmp(ap_id, FIXTURE_AP_ID) != 0 || !session_epoch ||
        strlen(session_epoch) != 64 || sequence < 1 ||
        observed_at <= 0 || received_at <= 0 || !snapshot_id ||
        strncmp(snapshot_id, "sha256:", 7) != 0 || strlen(snapshot_id) != 71 ||
        !report || strcmp(report->model, "Fixture AP 1") != 0 || !snapshot ||
        !json_object_object_get_ex(snapshot, "radios", &radios) ||
        !json_object_object_get_ex(snapshot, "ssids", &ssids) ||
        !json_object_object_get_ex(snapshot, "stations", &stations) ||
        json_object_array_length(radios) != 1 ||
        json_object_array_length(ssids) != 1 ||
        json_object_array_length(stations) != 1)
        return -1;
    if (sequence == telemetry_sequence &&
        observed_at == telemetry_observed_at &&
        strcmp(snapshot_id, telemetry_snapshot_id) == 0)
        return 0;
    telemetry_sequence = sequence;
    telemetry_observed_at = observed_at;
    snprintf(telemetry_snapshot_id, sizeof(telemetry_snapshot_id), "%s",
             snapshot_id);
    telemetry_count++;
    return fixture_count_write("telemetry-store-count", telemetry_count);
}
