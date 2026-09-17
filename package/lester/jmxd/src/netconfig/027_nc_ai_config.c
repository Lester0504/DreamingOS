            const char *effort = nc_text_or_empty(st, 5);
            const char *shape = nc_text_or_empty(st, 6);
            const char *auth_mode = nc_text_or_empty(st, 7);
            sqlite3_stmt *ins = NULL;

            nc_ai_provider_id_new(id);
            if (nc_prepare(&ins,
                "INSERT INTO ai_provider(id,provider,display_name,api_base,api_key,"
                "auth_mode,default_model,role,priority,weight,enabled,"
                "reasoning_effort,reasoning_api_shape,updated_at) "
                "VALUES(?1,?2,'',?3,?4,?5,?6,'primary',0,1,?7,?8,?9,?10)") != 0) {
                sqlite3_finalize(st);
                st = NULL;
                goto rollback;
            }
            sqlite3_bind_text(ins, 1, id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 2, provider, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 3, api_base, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 4, api_key, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 5, auth_mode[0] ? auth_mode : "api_key", -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 6, model, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(ins, 7, enabled ? 1 : 0);
            sqlite3_bind_text(ins, 8, effort[0] ? effort : "auto", -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 9, shape[0] ? shape : "chat_completions", -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(ins, 10, nc_now_s());
            if (nc_step_done(ins) != 0) {
                sqlite3_finalize(ins);
                sqlite3_finalize(st);
                st = NULL;
                goto rollback;
            }
            imported = sqlite3_changes(g_netconfig_db);
            sqlite3_finalize(ins);
        }
        sqlite3_finalize(st);
        st = NULL;
    }

    if (nc_prepare(&st,
        "INSERT OR IGNORE INTO ai_dispatch_policy(id,strategy,updated_at) "
        "VALUES(1,'single',?1)") != 0)
        goto rollback;
    sqlite3_bind_int64(st, 1, nc_now_s());
    if (nc_step_done(st) != 0)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;

    if (nc_prepare(&st,
        "INSERT INTO config_migration(name,status,source,imported_rows,imported_at,detail) "
        "VALUES(?1,'done','config.db:ai_config',?2,?3,?4)") != 0)
        goto rollback;
    sqlite3_bind_text(st, 1, NC_AI_MULTI_PROVIDER_MIGRATION, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, imported);
    sqlite3_bind_int64(st, 3, nc_now_s());
    sqlite3_bind_text(st, 4, imported ? "ai_config_row_promoted_to_primary_provider" :
                                        "no_legacy_ai_config_row", -1, SQLITE_STATIC);
    if (nc_step_done(st) != 0)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    return nc_txn_end(0);

rollback:
    if (st) sqlite3_finalize(st);
    nc_txn_end(-1);
    return -1;
}

static void nc_ai_db_init(void)
{
    nc_exec("CREATE TABLE IF NOT EXISTS ai_conversation ("
        "id TEXT PRIMARY KEY,"
        "title TEXT NOT NULL DEFAULT '',"
        "model TEXT NOT NULL DEFAULT '',"
        "message_count INTEGER NOT NULL DEFAULT 0,"
        "created_at INTEGER NOT NULL DEFAULT 0,"
        "updated_at INTEGER NOT NULL DEFAULT 0"
    ")");
    nc_exec("CREATE TABLE IF NOT EXISTS ai_message ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "conversation_id TEXT NOT NULL,"
        "role TEXT NOT NULL DEFAULT 'user',"
        "content TEXT NOT NULL DEFAULT '',"
        "ts INTEGER NOT NULL DEFAULT 0,"
        "sort_order INTEGER NOT NULL DEFAULT 0"
    ")");
    /* AI config: provider settings */
    nc_exec("CREATE TABLE IF NOT EXISTS ai_config ("
        "id INTEGER PRIMARY KEY CHECK (id = 1),"
        "provider TEXT NOT NULL DEFAULT 'openai',"
        "api_base TEXT NOT NULL DEFAULT '',"
        "api_key TEXT NOT NULL DEFAULT '',"
        "model TEXT NOT NULL DEFAULT 'gpt-4o',"
        "temperature REAL NOT NULL DEFAULT 0.7,"
        "max_tokens INTEGER NOT NULL DEFAULT 4096,"
        "system_prompt TEXT NOT NULL DEFAULT '',"
        "tool_policy TEXT NOT NULL DEFAULT 'confirm_medium',"
        "enabled INTEGER NOT NULL DEFAULT 0,"
        "reasoning_effort TEXT NOT NULL DEFAULT 'auto',"
        "reasoning_api_shape TEXT NOT NULL DEFAULT 'chat_completions',"
        "auth_mode TEXT NOT NULL DEFAULT 'api_key',"
        "updated_at INTEGER NOT NULL DEFAULT 0"
    ")");
    nc_add_column_if_missing("ai_config", "reasoning_effort", "TEXT NOT NULL DEFAULT 'auto'");
    nc_add_column_if_missing("ai_config", "reasoning_api_shape", "TEXT NOT NULL DEFAULT 'chat_completions'");
    nc_add_column_if_missing("ai_config", "auth_mode", "TEXT NOT NULL DEFAULT 'api_key'");
    /* AI tool registry: available tools + risk levels */
    nc_exec("CREATE TABLE IF NOT EXISTS ai_tool ("
        "id TEXT PRIMARY KEY,"
        "name TEXT NOT NULL DEFAULT '',"
        "title TEXT NOT NULL DEFAULT '',"
        "description TEXT NOT NULL DEFAULT '',"
        "parameters_json TEXT NOT NULL DEFAULT '{}',"
        "risk_level TEXT NOT NULL DEFAULT 'low',"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "category TEXT NOT NULL DEFAULT 'general',"
        "sort_order INTEGER NOT NULL DEFAULT 0"
    ")");
    /* AI tool authorization requests */
    nc_exec("CREATE TABLE IF NOT EXISTS ai_tool_auth ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "conversation_id TEXT NOT NULL DEFAULT '',"
        "tool_call_id TEXT NOT NULL DEFAULT '',"
        "tool_id TEXT NOT NULL DEFAULT '',"
        "parameters_json TEXT NOT NULL DEFAULT '{}',"
        "actor TEXT NOT NULL DEFAULT '',"
        "risk_level TEXT NOT NULL DEFAULT '',"
        "status TEXT NOT NULL DEFAULT 'pending',"
        "result_json TEXT NOT NULL DEFAULT '',"
        "error TEXT NOT NULL DEFAULT '',"
        "approved_by TEXT NOT NULL DEFAULT '',"
        "created_at INTEGER NOT NULL DEFAULT 0,"
        "resolved_at INTEGER NOT NULL DEFAULT 0"
    ")");
    nc_add_column_if_missing("ai_tool_auth", "tool_call_id", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("ai_tool_auth", "actor", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("ai_tool_auth", "risk_level", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("ai_tool_auth", "result_json", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("ai_tool_auth", "error", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("ai_tool_auth", "approved_by", "TEXT NOT NULL DEFAULT ''");
    nc_exec("CREATE UNIQUE INDEX IF NOT EXISTS ai_tool_auth_call_idx "
            "ON ai_tool_auth(conversation_id,tool_call_id) WHERE tool_call_id<>''");
    nc_exec("CREATE INDEX IF NOT EXISTS ai_tool_auth_status_idx "
            "ON ai_tool_auth(status,created_at)");
    /* Multi-provider: ai_config stays as the global default (temperature,
     * max_tokens, system_prompt, tool_policy); per-provider credentials and
     * the dispatch strategy live in the tables below. */
    nc_exec("CREATE TABLE IF NOT EXISTS ai_provider ("
        "id TEXT PRIMARY KEY,"
        "provider TEXT NOT NULL DEFAULT 'openai',"
        "display_name TEXT NOT NULL DEFAULT '',"
        "api_base TEXT NOT NULL DEFAULT '',"
        "api_key TEXT NOT NULL DEFAULT '',"
        "auth_mode TEXT NOT NULL DEFAULT 'api_key',"
        "default_model TEXT NOT NULL DEFAULT '',"
        "role TEXT NOT NULL DEFAULT 'standby',"
        "priority INTEGER NOT NULL DEFAULT 100,"
        "weight INTEGER NOT NULL DEFAULT 1,"
        "enabled INTEGER NOT NULL DEFAULT 0,"
        "reasoning_effort TEXT NOT NULL DEFAULT 'auto',"
        "reasoning_api_shape TEXT NOT NULL DEFAULT 'chat_completions',"
        "last_check_ts INTEGER NOT NULL DEFAULT 0,"
        "last_check_ok INTEGER NOT NULL DEFAULT -1,"
        "last_check_latency_ms INTEGER NOT NULL DEFAULT -1,"
        "last_check_error TEXT NOT NULL DEFAULT '',"
        "updated_at INTEGER NOT NULL DEFAULT 0"
    ")");
    nc_exec("CREATE INDEX IF NOT EXISTS ai_provider_dispatch_idx "
            "ON ai_provider(enabled,priority,id)");
    nc_exec("CREATE TABLE IF NOT EXISTS ai_provider_model ("
        "provider_id TEXT NOT NULL,"
        "model_id TEXT NOT NULL,"
        "display_name TEXT NOT NULL DEFAULT '',"
        "synced_at INTEGER NOT NULL DEFAULT 0,"
        "PRIMARY KEY (provider_id,model_id)"
    ")");
    nc_exec("CREATE TABLE IF NOT EXISTS ai_dispatch_policy ("
        "id INTEGER PRIMARY KEY CHECK (id = 1),"
        "strategy TEXT NOT NULL DEFAULT 'single',"
        "failover_timeout_ms INTEGER NOT NULL DEFAULT 20000,"
        "failover_max_attempts INTEGER NOT NULL DEFAULT 2,"
        /* webd is fork-per-request, so a purely in-memory round-robin cursor
         * would reset every request and load_balance would always pick the
         * first provider. The cursor has to be persisted to be real. */
