
    nc_adv_artifacts_init(artifacts, artifact_count);
    if (jmx_netconfig_db_init() != 0) {
        response_ok = 0;
        failed_stage = "database_init";
        reason = "advanced_routing_database_unavailable";
        apply_state = "failed";
        goto response;
    }
    nc_adv_route_db_init();
    if (dry) {
        json_object_array_add(warnings,
            json_object_new_string("dry_run: no files written and no runtime apply"));
        goto summary_query;
    }

#define NC_ADV_MKDIR(path, mode, stage) do { \
        struct stat dir_st; \
        if ((mkdir((path), (mode)) != 0 && errno != EEXIST) || \
            stat((path), &dir_st) != 0 || !S_ISDIR(dir_st.st_mode)) { \
            failed_stage = (stage); \
            reason = "advanced_routing_directory_prepare_failed"; \
            goto failed; \
        } \
    } while (0)
    NC_ADV_MKDIR("/etc/iproute2", 0755, "prepare_iproute2_directory");
    NC_ADV_MKDIR("/etc/iproute2/rt_tables.d", 0755, "prepare_rt_tables_directory");
    NC_ADV_MKDIR("/etc/dreamingwrt", 0755, "prepare_dreamingwrt_directory");
#undef NC_ADV_MKDIR

    if (nc_adv_recover_pending_publish() != 0) {
        failed_stage = "recover_pending_publish";
        reason = "advanced_routing_publish_recovery_failed";
        goto failed;
    }
    transaction_id = nc_adv_transaction_id();
    for (size_t i = 0; i < artifact_count; i++) {
        if (nc_adv_artifact_open(&artifacts[i], transaction_id, i) != 0) {
            failed_stage = "open_artifact_staging";
            reason = "advanced_routing_artifact_open_failed";
            goto failed;
        }
    }
    if (nc_adv_generate_rt_tables(artifacts[0].fp) != 0 ||
        nc_adv_artifact_finish(&artifacts[0]) != 0) {
        failed_stage = "generate_rt_tables";
        reason = "advanced_routing_artifact_write_failed";
        goto failed;
    }
    if (nc_adv_generate_draft_config(artifacts[1].fp) != 0 ||
        nc_adv_artifact_finish(&artifacts[1]) != 0) {
        failed_stage = "generate_draft_config";
        reason = "advanced_routing_artifact_write_failed";
        goto failed;
    }
    if (nc_adv_generate_runtime(artifacts[2].fp, artifacts[3].fp) != 0 ||
        nc_adv_artifact_finish(&artifacts[2]) != 0 ||
        nc_adv_artifact_finish(&artifacts[3]) != 0) {
        failed_stage = "generate_runtime_artifacts";
        reason = "advanced_routing_artifact_write_failed";
        goto failed;
    }
    if (nc_adv_artifacts_publish(artifacts, artifact_count, transaction_id,
                                 NC_ADV_JOURNAL_DIR) != 0) {
        failed_stage = "publish_runtime_artifacts";
        reason = "advanced_routing_artifact_publish_failed";
        goto failed;
    }
    artifact_generated = 1;
    apply_state = "staged";
    if (!apply_runtime) {
        reason = "runtime_apply_not_requested";
        if (nc_adv_set_apply_state(apply_state, 0) != 0) {
            failed_stage = "persist_staged_state";
            reason = "advanced_routing_state_update_failed";
            goto failed;
        }
        goto summary_query;
    }

    runtime_attempted = 1;
    {
        int logfd = nc_adv_open_runtime_log(log_path, sizeof(log_path));
        if (logfd < 0) {
            apply_rc = -1;
            failed_stage = "open_runtime_log";
            reason = "advanced_routing_runtime_log_failed";
            goto failed;
        }
        apply_rc = nc_adv_run_script(logfd);
    }
    if (apply_rc != 0) {
        failed_stage = "runtime_apply";
        reason = "advanced_routing_runtime_apply_failed";
        goto failed;
    }
    if (nc_adv_runtime_readback(runtime_readback_reason,
                                sizeof(runtime_readback_reason)) != 0) {
        failed_stage = "runtime_readback";
        reason = runtime_readback_reason[0]
            ? runtime_readback_reason
            : "advanced_routing_runtime_readback_failed";
        goto failed;
    }
    runtime_applied = 1;
    readback_verified = 1;
    apply_state = "applied";
    reason = "applied";
    if (nc_adv_set_apply_state(apply_state, 1) != 0) {
        failed_stage = "persist_runtime_state";
        reason = "advanced_routing_state_update_failed";
        goto failed;
    }
    goto summary_query;

failed:
    response_ok = 0;
    apply_state = "failed";
    nc_adv_artifacts_abort(artifacts, artifact_count, 0);
    if (g_netconfig_db && nc_adv_set_apply_state("failed", 0) != 0 &&
        strcmp(failed_stage, "database_init") != 0) {
        failed_stage = "persist_failure_state";
        reason = "advanced_routing_state_update_failed";
    }

summary_query:
    if (g_netconfig_db && nc_prepare(&st,
        "SELECT (SELECT COUNT(*) FROM route_table),(SELECT COUNT(*) FROM static_route),"
        "(SELECT COUNT(*) FROM route_object),(SELECT COUNT(*) FROM cross_l3_service),"
        "(SELECT COUNT(*) FROM policy_route_rule)") == 0) {
        int step_rc = sqlite3_step(st);
        if (step_rc == SQLITE_ROW) {
            tables = sqlite3_column_int(st, 0);
            routes = sqlite3_column_int(st, 1);
            objects = sqlite3_column_int(st, 2);
            cross = sqlite3_column_int(st, 3);
            rules = sqlite3_column_int(st, 4);
        } else if (response_ok) {
            response_ok = 0;
            failed_stage = "summary_query";
            reason = "advanced_routing_database_read_failed";
            apply_state = "failed";
        }
        if (sqlite3_finalize(st) != SQLITE_OK && response_ok) {
            response_ok = 0;
            failed_stage = "summary_finalize";
            reason = "advanced_routing_database_read_failed";
            apply_state = "failed";
        }
        st = NULL;
    } else if (g_netconfig_db && response_ok) {
        response_ok = 0;
        failed_stage = "summary_prepare";
        reason = "advanced_routing_database_read_failed";
        apply_state = "failed";
    }

response:
