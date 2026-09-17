
/* ═══════════════════════════════════════════════════════════════════════════
 * AI Conversation History
 * ═══════════════════════════════════════════════════════════════════════════ */
static const char *nc_text_or_empty(sqlite3_stmt *st, int col)
{
    const char *v = st ? (const char *)sqlite3_column_text(st, col) : NULL;
    return v ? v : "";
}

static int nc_ai_provider_id_new(char out[33])
{
    if (!out)
        return -1;
    if (nc_random_hex(out, 32) != 0) {
        snprintf(out, 33, "%016llx%016llx",
                 (unsigned long long)nc_now_s(),
                 (unsigned long long)(uintptr_t)out);
        return 0;
    }
    return 0;
}

/*
 * One-way, idempotent move of the single ai_config row into ai_provider.
 * ai_config is deliberately kept: it still holds the session-level defaults
 * (temperature / max_tokens / system_prompt / tool_policy) and the old
 * /api/v1/ai/config readers (iOS app, web) must keep working.
 */
static int nc_ai_multi_provider_migrate_once(void)
{
    sqlite3_stmt *st = NULL;
    char id[33] = "";
    int have_legacy = 0;
    int provider_rows = 0;
    int imported = 0;

    if (nc_prepare(&st,
        "SELECT 1 FROM config_migration WHERE name=?1 AND status='done'") != 0)
        return -1;
    sqlite3_bind_text(st, 1, NC_AI_MULTI_PROVIDER_MIGRATION, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        sqlite3_finalize(st);
        return 0;
    }
    sqlite3_finalize(st);
    st = NULL;

    if (nc_txn_begin() != 0)
        return -1;

    if (nc_prepare(&st, "SELECT COUNT(*) FROM ai_provider") != 0)
        goto rollback;
    if (sqlite3_step(st) == SQLITE_ROW)
        provider_rows = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    st = NULL;

    if (provider_rows == 0) {
        if (nc_prepare(&st,
            "SELECT provider,api_base,api_key,model,enabled,reasoning_effort,"
            "reasoning_api_shape,auth_mode FROM ai_config WHERE id=1") != 0)
            goto rollback;
        have_legacy = sqlite3_step(st) == SQLITE_ROW;
        if (have_legacy) {
            const char *provider = nc_text_or_empty(st, 0);
            const char *api_base = nc_text_or_empty(st, 1);
            const char *api_key = nc_text_or_empty(st, 2);
            const char *model = nc_text_or_empty(st, 3);
            int enabled = sqlite3_column_int(st, 4);
