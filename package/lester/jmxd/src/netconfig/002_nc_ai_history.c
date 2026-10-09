/* ══════════════════════════════════════════════════════════════════════
 * AI history helpers
 * ══════════════════════════════════════════════════════════════════════ */

static struct json_object *nc_ai_history_usage(int prompt, int completion, int total)
{
    if (prompt < 0 || completion < 0 || total < 0) return NULL;
    struct json_object *u = json_object_new_object();
    json_object_object_add(u, "prompt_tokens", json_object_new_int(prompt));
    json_object_object_add(u, "completion_tokens", json_object_new_int(completion));
    json_object_object_add(u, "total_tokens", json_object_new_int(total));
    json_object_object_add(u, "usage_verified", json_object_new_boolean(0));
    json_object_object_add(u, "source", json_object_new_string("provider_or_client_reported"));
    return u;
}

static struct json_object *nc_ai_history_error(const char *error, const char *message,
                                                const char *field)
{
    struct json_object *d = json_object_new_object();

    json_object_object_add(d, "ok", json_object_new_boolean(0));
    json_object_object_add(d, "error", json_object_new_string(error ? error : "storage_error"));
    if (message && message[0])
        json_object_object_add(d, "message", json_object_new_string(message));
    if (field && field[0])
        json_object_object_add(d, "field", json_object_new_string(field));
    return jmx_gen_api_response_data(API_CODE_ERROR, d);
}

static int nc_ai_public_id_ok(const char *id)
{
    const unsigned char *p = (const unsigned char *)id;
    size_t len;

    if (!id || !id[0])
        return 0;
    len = strlen(id);
    if (len > NC_AI_CONVERSATION_ID_MAX)
        return 0;
    for (; *p; p++) {
        if (isalnum(*p) || *p == '_' || *p == '-' || *p == '.' || *p == ':')
            continue;
        return 0;
    }
    return 1;
}

static int nc_ai_role_ok(const char *role)
{
    return role && (!strcmp(role, "system") || !strcmp(role, "user") ||
                    !strcmp(role, "assistant") || !strcmp(role, "tool"));
}

static sqlite3_int64 nc_ai_json_i64(struct json_object *obj, const char *key,
                                    sqlite3_int64 def)
{
    struct json_object *value = NULL;

    if (!obj || !json_object_object_get_ex(obj, key, &value) || !value)
        return def;
    return (sqlite3_int64)json_object_get_int64(value);
}

static char *nc_ai_attachments_metadata_json(struct json_object *message)
{
    struct json_object *input = NULL;
    struct json_object *output = json_object_new_array();
    const char *encoded;
    char *copy;

    if (!output)
        return NULL;
    if (message && json_object_object_get_ex(message, "attachments", &input) && input &&
        json_object_is_type(input, json_type_array)) {
        int count = json_object_array_length(input);
        for (int i = 0; i < count; i++) {
            struct json_object *src = json_object_array_get_idx(input, i);
            struct json_object *dst;
            const char *name;
            const char *type;
            const char *attachment_id;
            sqlite3_int64 size;

            if (!src || !json_object_is_type(src, json_type_object))
                continue;
            name = nc_json_str_def(src, "name", nc_json_str_def(src, "filename", ""));
            type = nc_json_str_def(src, "type", "");
            attachment_id = nc_json_str_def(src, "attachment_id", "");
            size = nc_ai_json_i64(src, "size", 0);
            dst = json_object_new_object();
            if (!dst) {
                json_object_put(output);
                return NULL;
            }
            json_object_object_add(dst, "name", json_object_new_string(name));
            json_object_object_add(dst, "type", json_object_new_string(type));
            json_object_object_add(dst, "size", json_object_new_int64(size));
            if (attachment_id[0])
                json_object_object_add(dst, "attachment_id",
                                       json_object_new_string(attachment_id));
            json_object_array_add(output, dst);
        }
    }
    encoded = json_object_to_json_string_ext(output, JSON_C_TO_STRING_PLAIN);
    copy = encoded ? strdup(encoded) : NULL;
    json_object_put(output);
    return copy;
}

static struct json_object *nc_ai_attachments_from_text(const char *raw)
{
    struct json_object *parsed = raw && raw[0] ? json_tokener_parse(raw) : NULL;

    if (!parsed || !json_object_is_type(parsed, json_type_array)) {
        if (parsed)
            json_object_put(parsed);
        return json_object_new_array();
    }
    return parsed;
}

/* Identity comes from the authenticated transport, never a client-selected owner.
 * Empty owners are retained legacy records and deliberately cannot be claimed. */
static int nc_ai_history_actor_ok(const char *actor)
{
    if (!actor || !actor[0] || strlen(actor) > 159) return 0;
    for (const unsigned char *p = (const unsigned char *)actor; *p; p++)
        if (*p < 0x20 || *p == 0x7f) return 0;
    return 1;
}

static char *nc_ai_message_metadata(struct json_object *message)
{
    struct json_object *meta = json_object_new_object(), *value = NULL;
    const char *keys[] = { "execution_backend", "provider", "model", "response_id", "status", NULL };
    for (int i = 0; keys[i]; i++) {
        const char *v = nc_json_str_def(message, keys[i], "");
        if (v[0] && strlen(v) <= 160)
            json_object_object_add(meta, keys[i], json_object_new_string(v));
    }
    if (json_object_object_get_ex(message, "usage", &value) && value &&
        json_object_is_type(value, json_type_object)) {
        int p = nc_json_int_def(value, "prompt_tokens", -1);
        int c = nc_json_int_def(value, "completion_tokens", -1);
        int t = nc_json_int_def(value, "total_tokens", -1);
        json_object_object_add(meta, "usage", nc_ai_history_usage(p, c, t));
    }
    char *encoded = strdup(json_object_to_json_string_ext(meta, JSON_C_TO_STRING_PLAIN));
    json_object_put(meta);
    return encoded;
}

struct json_object *jmx_ai_history_list(const char *actor, int limit, int offset, const char *q)
{
    if (!nc_ai_history_actor_ok(actor))
        return nc_ai_history_error("identity_required", "Authenticated subject is required", "actor");

    if (!q) q = "";
    if (strlen(q) > 256) return nc_ai_history_error("invalid_query", "Search exceeds 256 bytes", "q");
    int total = 0;
    int step_rc;

    if (jmx_netconfig_db_init() != 0)
        return nc_ai_history_error("storage_error", "AI history database is unavailable", "database");
    struct json_object *d = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    if (limit <= 0 || limit > 200) limit = 50;
    if (offset < 0) offset = 0;
    if (!d || !arr) {
        if (d) json_object_put(d);
        if (arr) json_object_put(arr);
        return nc_ai_history_error("storage_error", "AI history response allocation failed", "response");
    }
    if (nc_prepare(&st, "SELECT COUNT(*) FROM ai_conversation WHERE owner=?1 AND (?2='' OR instr(lower(title),lower(?2))>0 OR EXISTS (SELECT 1 FROM ai_message m WHERE m.conversation_id=ai_conversation.id AND m.role!='system' AND instr(lower(m.content),lower(?2))>0))") != 0 ||
        sqlite3_bind_text(st, 1, actor, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 2, q, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        json_object_put(d);
        json_object_put(arr);
        return nc_ai_history_error("storage_error", "AI history count query failed", "database");
    }
    step_rc = sqlite3_step(st);
    if (step_rc != SQLITE_ROW) {
        sqlite3_finalize(st);
        json_object_put(d);
        json_object_put(arr);
        return nc_ai_history_error("storage_error", "AI history count query failed", "database");
    }
    total = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&st,
        "SELECT id, title, model, reasoning_effort, created_at, updated_at,"
        " message_count, prompt_tokens, completion_tokens, total_tokens, revision, execution_backend, provider"
        " FROM ai_conversation WHERE owner=?1 AND (?2='' OR instr(lower(title),lower(?2))>0 OR EXISTS (SELECT 1 FROM ai_message m WHERE m.conversation_id=ai_conversation.id AND m.role!='system' AND instr(lower(m.content),lower(?2))>0)) ORDER BY updated_at DESC, id ASC LIMIT ?3 OFFSET ?4") != 0 ||
        sqlite3_bind_text(st, 1, actor, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 2, q, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int(st, 3, limit) != SQLITE_OK ||
        sqlite3_bind_int(st, 4, offset) != SQLITE_OK) {
        if (st) sqlite3_finalize(st);
        json_object_put(d);
        json_object_put(arr);
        return nc_ai_history_error("storage_error", "AI history list query failed", "database");
    }
    while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            nc_add_text(o, "id", st, 0);
            nc_add_text(o, "title", st, 1);
            nc_add_text(o, "model", st, 2);
            nc_add_text(o, "reasoning_effort", st, 3);
            json_object_object_add(o, "created_at", json_object_new_int64(sqlite3_column_int64(st, 4)));
            json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 5)));
            json_object_object_add(o, "message_count", json_object_new_int(sqlite3_column_int(st, 6)));
            json_object_object_add(o, "usage", nc_ai_history_usage(
                sqlite3_column_int(st, 7), sqlite3_column_int(st, 8), sqlite3_column_int(st, 9)));
            json_object_object_add(o, "usage_verified", json_object_new_boolean(0));
            json_object_object_add(o, "revision", json_object_new_int64(sqlite3_column_int64(st, 10)));
            nc_add_text(o, "execution_backend", st, 11);
            nc_add_text(o, "provider", st, 12);
            json_object_array_add(arr, o);
    }
    if (step_rc != SQLITE_DONE) {
        sqlite3_finalize(st);
        json_object_put(d);
        json_object_put(arr);
        return nc_ai_history_error("storage_error", "AI history list query failed", "database");
    }
    sqlite3_finalize(st);
    json_object_object_add(d, "ok", json_object_new_boolean(1));
    json_object_object_add(d, "items", arr);
    json_object_object_add(d, "limit", json_object_new_int(limit));
    json_object_object_add(d, "offset", json_object_new_int(offset));
    json_object_object_add(d, "total", json_object_new_int(total));
    json_object_object_add(d, "has_more", json_object_new_boolean(offset + json_object_array_length(arr) < total));
    json_object_object_add(d, "q", json_object_new_string(q));
    json_object_object_add(d, "search_scope", json_object_new_string("title_and_visible_messages"));
    json_object_object_add(d, "ownership", json_object_new_string("authenticated_subject"));
    json_object_object_add(d, "legacy_unowned", json_object_new_string("preserved_hidden"));
    json_object_object_add(d, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

struct json_object *jmx_ai_history_get(const char *actor, const char *id)
{
    if (!nc_ai_history_actor_ok(actor))
        return nc_ai_history_error("identity_required", "Authenticated subject is required", "actor");

    int step_rc;

    if (!nc_ai_public_id_ok(id))
        return nc_ai_history_error("invalid_id", "Conversation ID is invalid", "id");
    if (jmx_netconfig_db_init() != 0)
        return nc_ai_history_error("storage_error", "AI history database is unavailable", "database");
    struct json_object *d = json_object_new_object();
    struct json_object *item = json_object_new_object();
    struct json_object *messages = json_object_new_array();
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st,
        "SELECT id, title, model, reasoning_effort, created_at, updated_at,"
        " message_count, prompt_tokens, completion_tokens, total_tokens, revision, execution_backend, provider"
        " FROM ai_conversation WHERE id=?1 AND owner=?2") != 0 ||
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 2, actor, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        if (st) sqlite3_finalize(st);
        json_object_put(d);
        json_object_put(item);
        json_object_put(messages);
        return nc_ai_history_error("storage_error", "AI history lookup failed", "database");
    }
    step_rc = sqlite3_step(st);
    if (step_rc == SQLITE_ROW) {
            nc_add_text(item, "id", st, 0);
            nc_add_text(item, "title", st, 1);
            nc_add_text(item, "model", st, 2);
            nc_add_text(item, "reasoning_effort", st, 3);
            json_object_object_add(item, "created_at", json_object_new_int64(sqlite3_column_int64(st, 4)));
            json_object_object_add(item, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 5)));
            json_object_object_add(item, "message_count", json_object_new_int(sqlite3_column_int(st, 6)));
            json_object_object_add(item, "usage", nc_ai_history_usage(
                sqlite3_column_int(st, 7), sqlite3_column_int(st, 8), sqlite3_column_int(st, 9)));
            json_object_object_add(item, "revision", json_object_new_int64(sqlite3_column_int64(st, 10)));
            nc_add_text(item, "execution_backend", st, 11);
            nc_add_text(item, "provider", st, 12);
            json_object_object_add(item, "usage_verified", json_object_new_boolean(0));
    } else if (step_rc == SQLITE_DONE) {
        sqlite3_finalize(st);
        json_object_put(d);
        json_object_put(item);
        json_object_put(messages);
        return nc_ai_history_error("not_found", "Conversation was not found", "id");
    } else {
        sqlite3_finalize(st);
        json_object_put(d);
        json_object_put(item);
        json_object_put(messages);
        return nc_ai_history_error("storage_error", "AI history lookup failed", "database");
    }
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&st,
        "SELECT message_id, role, content, attachments_json, created_at, metadata_json"
        " FROM ai_message WHERE conversation_id=?1 ORDER BY id") != 0 ||
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        if (st) sqlite3_finalize(st);
        json_object_put(d);
        json_object_put(item);
        json_object_put(messages);
        return nc_ai_history_error("storage_error", "AI history messages query failed", "database");
    }
    while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) {
            struct json_object *m = json_object_new_object();
            const char *message_id = (const char *)sqlite3_column_text(st, 0);
            const char *attachments = (const char *)sqlite3_column_text(st, 3);
            json_object_object_add(m, "message_id", json_object_new_string(message_id ? message_id : ""));
            json_object_object_add(m, "id", json_object_new_string(message_id ? message_id : ""));
            nc_add_text(m, "role", st, 1);
            nc_add_text(m, "content", st, 2);
            json_object_object_add(m, "attachments", nc_ai_attachments_from_text(attachments));
            json_object_object_add(m, "created_at", json_object_new_int64(sqlite3_column_int64(st, 4)));
            struct json_object *meta = json_tokener_parse((const char *)sqlite3_column_text(st, 5));
            if (meta && json_object_is_type(meta, json_type_object)) {
                const char *keys[] = { "execution_backend", "provider", "model", "response_id", "status", "usage", NULL };
                for (int k = 0; keys[k]; k++) {
                    struct json_object *v = NULL;
                    if (json_object_object_get_ex(meta, keys[k], &v))
                        json_object_object_add(m, keys[k], json_object_get(v));
                }
            }
            if (meta) json_object_put(meta);
            json_object_array_add(messages, m);
    }
    if (step_rc != SQLITE_DONE) {
        sqlite3_finalize(st);
        json_object_put(d);
        json_object_put(item);
        json_object_put(messages);
        return nc_ai_history_error("storage_error", "AI history messages query failed", "database");
    }
    sqlite3_finalize(st);
    json_object_object_add(item, "messages", messages);
    json_object_object_add(d, "ok", json_object_new_boolean(1));
    json_object_object_add(d, "item", item);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

static char *nc_ai_sanitize_message(const char *in)
{
    if (!in || !in[0]) return strdup("");
    size_t len = strlen(in);
    size_t cap = len + 64;
    char *out = calloc(1, cap);
    if (!out) return NULL;
    const char *p = in;
    size_t w = 0;
    while (*p) {
        const char *sensitive = NULL;
        if (!strncasecmp(p, "api_key", 7)) sensitive = p + 7;
        else if (!strncasecmp(p, "apiKey", 6)) sensitive = p + 6;
        else if (!strncasecmp(p, "bearer ", 7)) sensitive = p + 7;
        else if (!strncasecmp(p, "authorization: ", 15)) sensitive = p + 15;
        else if (!strncasecmp(p, "password", 8)) sensitive = p + 8;
        else if (!strncasecmp(p, "token", 5)) sensitive = p + 5;
        else if (!strncasecmp(p, "secret", 6)) sensitive = p + 6;
        if (sensitive) {
            size_t prefix = (size_t)(sensitive - p);
            if (w + prefix + 8 > cap) { cap = w + prefix + 64; out = realloc(out, cap); if (!out) return NULL; }
            memcpy(out + w, p, prefix); w += prefix;
            while (*sensitive && (*sensitive == ' ' || *sensitive == '"' || *sensitive == ':' || *sensitive == '=')) out[w++] = *sensitive++;
            size_t masked = 0;
            while (*sensitive && *sensitive != ',' && *sensitive != '"' && *sensitive != '}' && *sensitive != '\n' && *sensitive != ' ') { sensitive++; masked = 1; }
            if (masked) { const char *m = "***"; memcpy(out + w, m, 3); w += 3; }
            p = sensitive;
            continue;
        }
        if (w + 1 >= cap) { cap = w + 64; out = realloc(out, cap); if (!out) return NULL; }
        out[w++] = *p++;
    }
    out[w] = 0;
    return out;
}

struct json_object *jmx_ai_history_save(const char *actor, struct json_object *req)
{
    if (!nc_ai_history_actor_ok(actor))
        return nc_ai_history_error("identity_required", "Authenticated subject is required", "actor");

    sqlite3_stmt *st = NULL;
    sqlite3_stmt *ms = NULL;
    struct json_object *messages = NULL;
    sqlite3_int64 now = (sqlite3_int64)nc_now_s();
    int requested_count = 0;
    int inserted_count = 0;
    size_t total_content = 0;
    int tx_started = 0;

    if (!req || !json_object_is_type(req, json_type_object))
        return nc_ai_history_error("invalid_request", "History payload must be an object", "body");
    if (jmx_netconfig_db_init() != 0)
        return nc_ai_history_error("storage_error", "AI history database is unavailable", "database");
    struct json_object *usage = NULL;
    const char *id = nc_json_str_def(req, "id", "");
    const char *title = nc_json_str_def(req, "title", "");
    const char *model = nc_json_str_def(req, "model", "");
    const char *effort = nc_json_str_def(req, "reasoning_effort", "auto");
    int prompt_tok = -1, completion_tok = -1, total_tok = -1;
    sqlite3_int64 revision = 0;
    struct json_object *submitted_revision = NULL;
    if (json_object_object_get_ex(req, "revision", &submitted_revision) &&
        (!json_object_is_type(submitted_revision, json_type_int) || json_object_get_int64(submitted_revision) < 0))
        return nc_ai_history_error("invalid_revision", "revision must be a nonnegative integer", "revision");
    const char *backend = nc_json_str_def(req, "execution_backend", "api");
    const char *provider = nc_json_str_def(req, "provider", "");
    if ((strcmp(backend, "api") && strcmp(backend, "local")) || strlen(provider) > 128)
        return nc_ai_history_error("invalid_source", "Execution source is invalid", "execution_backend");
    if (json_object_object_get_ex(req, "usage", &usage) && usage) {
        prompt_tok = nc_json_int_def(usage, "prompt_tokens", -1);
        completion_tok = nc_json_int_def(usage, "completion_tokens", -1);
        total_tok = nc_json_int_def(usage, "total_tokens", -1);
    }
    char conv_id[NC_AI_CONVERSATION_ID_MAX + 1];
    if (id[0]) {
        if (!nc_ai_public_id_ok(id))
            return nc_ai_history_error("invalid_id", "Conversation ID is invalid", "id");
        snprintf(conv_id, sizeof(conv_id), "%s", id);
    } else {
        unsigned int random_part = 0;
        sqlite3_randomness((int)sizeof(random_part), &random_part);
        snprintf(conv_id, sizeof(conv_id), "ai-%lld-%08x", (long long)now, random_part);
    }
    if (strlen(title) > NC_AI_TITLE_MAX)
        return nc_ai_history_error("invalid_title", "Title exceeds 512 bytes", "title");
    if (strlen(model) > NC_AI_MODEL_MAX)
        return nc_ai_history_error("invalid_model", "Model exceeds 128 bytes", "model");
    if (strlen(effort) > NC_AI_EFFORT_MAX)
        return nc_ai_history_error("invalid_reasoning_effort", "Reasoning effort is too long", "reasoning_effort");
    if (json_object_object_get_ex(req, "messages", &messages) && messages &&
        !json_object_is_type(messages, json_type_array))
        return nc_ai_history_error("invalid_messages", "Messages must be an array", "messages");
    if (messages)
        requested_count = json_object_array_length(messages);
    if (requested_count > NC_AI_MESSAGES_MAX)
        return nc_ai_history_error("too_many_messages", "A conversation may contain at most 512 messages", "messages");
    for (int i = 0; i < requested_count; i++) {
        struct json_object *m = json_object_array_get_idx(messages, i);
        struct json_object *attachments = NULL;
        const char *role;
        const char *raw;
        const char *message_id;
        int attachment_count = 0;

        if (!m || !json_object_is_type(m, json_type_object))
            return nc_ai_history_error("invalid_message", "Each message must be an object", "messages");
        role = nc_json_str_def(m, "role", "");
        raw = nc_json_str_def(m, "content", "");
        message_id = nc_json_str_def(m, "message_id", nc_json_str_def(m, "id", ""));
        if (!nc_ai_role_ok(role))
            return nc_ai_history_error("invalid_message_role", "Message role is invalid", "messages.role");
        if (message_id[0] && !nc_ai_public_id_ok(message_id))
            return nc_ai_history_error("invalid_message_id", "Message ID is invalid", "messages.message_id");
        if (message_id[0]) {
            for (int j = 0; j < i; j++) {
                struct json_object *previous = json_object_array_get_idx(messages, j);
                const char *previous_id = nc_json_str_def(previous, "message_id",
                                                         nc_json_str_def(previous, "id", ""));
                if (previous_id[0] && !strcmp(previous_id, message_id))
                    return nc_ai_history_error("duplicate_message_id",
                                               "Message IDs must be unique within a conversation",
                                               "messages.message_id");
            }
        }
        if (strlen(raw) > NC_AI_MESSAGE_CONTENT_MAX)
            return nc_ai_history_error("message_too_large", "Message content exceeds 256 KiB", "messages.content");
        total_content += strlen(raw);
        if (total_content > NC_AI_HISTORY_CONTENT_MAX)
            return nc_ai_history_error("conversation_too_large", "Conversation content exceeds 4 MiB", "messages.content");
        if (json_object_object_get_ex(m, "attachments", &attachments) && attachments) {
            if (!json_object_is_type(attachments, json_type_array))
                return nc_ai_history_error("invalid_attachments", "Attachments must be an array", "messages.attachments");
            attachment_count = json_object_array_length(attachments);
        }
        if (attachment_count > NC_AI_ATTACHMENTS_MAX)
            return nc_ai_history_error("too_many_attachments", "A message may contain at most 8 attachments", "messages.attachments");
        for (int j = 0; j < attachment_count; j++) {
            struct json_object *a = json_object_array_get_idx(attachments, j);
            const char *name;
            const char *type;
            const char *attachment_id;
            sqlite3_int64 size;
            if (!a || !json_object_is_type(a, json_type_object))
                return nc_ai_history_error("invalid_attachment", "Each attachment must be an object", "messages.attachments");
            name = nc_json_str_def(a, "name", nc_json_str_def(a, "filename", ""));
            type = nc_json_str_def(a, "type", "");
            attachment_id = nc_json_str_def(a, "attachment_id", "");
            size = nc_ai_json_i64(a, "size", 0);
            if (!name[0] || strlen(name) > NC_AI_ATTACHMENT_NAME_MAX)
                return nc_ai_history_error("invalid_attachment_name", "Attachment name is invalid", "messages.attachments.name");
            if (strlen(type) > NC_AI_ATTACHMENT_TYPE_MAX)
                return nc_ai_history_error("invalid_attachment_type", "Attachment type is too long", "messages.attachments.type");
            if (size < 0 || size > 512 * 1024)
                return nc_ai_history_error("invalid_attachment_size", "Attachment size exceeds 512 KiB", "messages.attachments.size");
            if (attachment_id[0]) {
                size_t id_len = strlen(attachment_id);
                if (id_len != 36 || strncmp(attachment_id, "att-", 4))
                    return nc_ai_history_error("invalid_attachment_id", "Attachment ID is invalid", "messages.attachments.attachment_id");
                for (size_t k = 4; k < id_len; k++)
                    if (!isxdigit((unsigned char)attachment_id[k]))
                        return nc_ai_history_error("invalid_attachment_id", "Attachment ID is invalid", "messages.attachments.attachment_id");
            }
        }
    }
    if (usage && (prompt_tok < 0 || completion_tok < 0 || total_tok < 0))
        return nc_ai_history_error("invalid_usage", "Token usage values must be non-negative", "usage");

    if (nc_exec("BEGIN IMMEDIATE") != 0)
        return nc_ai_history_error("storage_error", "Could not start AI history transaction", "database");
    tx_started = 1;
    if (nc_prepare(&st, "SELECT owner,revision FROM ai_conversation WHERE id=?1") != 0 ||
        sqlite3_bind_text(st, 1, conv_id, -1, SQLITE_TRANSIENT) != SQLITE_OK)
        goto storage_failed;
    int found = sqlite3_step(st);
    const char *conflict = NULL;
    if (found == SQLITE_ROW) {
        const char *owner = (const char *)sqlite3_column_text(st, 0);
        revision = sqlite3_column_int64(st, 1);
        if (!owner || strcmp(owner, actor)) conflict = "not_found";
        else if (nc_ai_json_i64(req, "revision", -1) != revision) conflict = "conversation_conflict";
    } else if (found != SQLITE_DONE) goto storage_failed;
    else if (nc_ai_json_i64(req, "revision", 0) != 0) conflict = "conversation_conflict";
    sqlite3_finalize(st);
    st = NULL;
    if (conflict) {
        nc_exec("ROLLBACK");
        return nc_ai_history_error(conflict, !strcmp(conflict, "not_found") ?
            "Conversation was not found" : "Conversation changed; reload before saving", "revision");
    }
    revision++;
    if (nc_prepare(&st,
        "INSERT INTO ai_conversation(id, title, model, reasoning_effort, message_count,"
        " prompt_tokens, completion_tokens, total_tokens, created_at, updated_at, owner, revision, execution_backend, provider)"
        " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?9,?10,?11,?12,?13)"
        " ON CONFLICT(id) DO UPDATE SET title=excluded.title, model=excluded.model,"
        " reasoning_effort=excluded.reasoning_effort, message_count=excluded.message_count,"
        " prompt_tokens=excluded.prompt_tokens, completion_tokens=excluded.completion_tokens,"
        " total_tokens=excluded.total_tokens, updated_at=excluded.updated_at, revision=excluded.revision,"
        " execution_backend=excluded.execution_backend, provider=excluded.provider") != 0 ||
        sqlite3_bind_text(st, 1, conv_id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 2, title[0] ? title : "未命名对话", -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 3, model, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 4, effort, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int(st, 5, 0) != SQLITE_OK ||
        sqlite3_bind_int(st, 6, prompt_tok) != SQLITE_OK ||
        sqlite3_bind_int(st, 7, completion_tok) != SQLITE_OK ||
        sqlite3_bind_int(st, 8, total_tok) != SQLITE_OK ||
        sqlite3_bind_int64(st, 9, now) != SQLITE_OK ||
        sqlite3_bind_text(st, 10, actor, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(st, 11, revision) != SQLITE_OK ||
        sqlite3_bind_text(st, 12, backend, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 13, provider, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        nc_step_done(st) != 0)
        goto storage_failed;
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&st, "DELETE FROM ai_message WHERE conversation_id=?1") != 0 ||
        sqlite3_bind_text(st, 1, conv_id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        nc_step_done(st) != 0)
        goto storage_failed;
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&ms,
        "INSERT INTO ai_message(conversation_id,message_id,role,content,attachments_json,created_at,metadata_json)"
        " VALUES(?1,?2,?3,?4,?5,?6,?7)") != 0)
        goto storage_failed;
    for (int i = 0; i < requested_count; i++) {
            struct json_object *m = json_object_array_get_idx(messages, i);
            const char *role = nc_json_str_def(m, "role", "user");
            const char *raw = nc_json_str_def(m, "content", "");
            const char *provided_id = nc_json_str_def(m, "message_id", nc_json_str_def(m, "id", ""));
            char generated_id[NC_AI_CONVERSATION_ID_MAX + 1];
            const char *message_id = provided_id;
            char *safe = nc_ai_sanitize_message(raw);
            char *attachments_json = nc_ai_attachments_metadata_json(m);
            char *metadata_json = nc_ai_message_metadata(m);
            sqlite3_int64 mts = nc_ai_json_i64(m, "created_at", now);
            if (mts <= 0) mts = now;
            if (!message_id[0]) {
                snprintf(generated_id, sizeof(generated_id), "msg-%lld-%d", (long long)mts, i);
                message_id = generated_id;
            }
            if (!safe || !attachments_json || !metadata_json ||
                sqlite3_bind_text(ms, 1, conv_id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
                sqlite3_bind_text(ms, 2, message_id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
                sqlite3_bind_text(ms, 3, role, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
                sqlite3_bind_text(ms, 4, safe ? safe : "", -1, SQLITE_TRANSIENT) != SQLITE_OK ||
                sqlite3_bind_text(ms, 5, attachments_json ? attachments_json : "[]", -1, SQLITE_TRANSIENT) != SQLITE_OK ||
                sqlite3_bind_text(ms, 7, metadata_json ? metadata_json : "{}", -1, SQLITE_TRANSIENT) != SQLITE_OK ||
                sqlite3_bind_int64(ms, 6, mts) != SQLITE_OK || nc_step_done(ms) != 0) {
                free(safe);
                free(attachments_json);
            free(metadata_json);
                goto storage_failed;
            }
            inserted_count++;
            free(safe);
            free(attachments_json);
            free(metadata_json);
            sqlite3_reset(ms);
            sqlite3_clear_bindings(ms);
    }
    sqlite3_finalize(ms);
    ms = NULL;
    if (nc_prepare(&st, "UPDATE ai_conversation SET message_count=?1 WHERE id=?2") != 0 ||
        sqlite3_bind_int(st, 1, inserted_count) != SQLITE_OK ||
        sqlite3_bind_text(st, 2, conv_id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        nc_step_done(st) != 0)
        goto storage_failed;
    sqlite3_finalize(st);
    st = NULL;
    if (nc_exec("COMMIT") != 0)
        goto storage_failed;
    tx_started = 0;
    struct json_object *d = json_object_new_object();
    json_object_object_add(d, "ok", json_object_new_boolean(1));
    json_object_object_add(d, "id", json_object_new_string(conv_id));
    json_object_object_add(d, "revision", json_object_new_int64(revision));
    json_object_object_add(d, "message_count", json_object_new_int(inserted_count));
    json_object_object_add(d, "usage_verified", json_object_new_boolean(0));
    json_object_object_add(d, "ts", json_object_new_int64(now));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);

storage_failed:
    if (st) sqlite3_finalize(st);
    st = NULL;
    st = NULL;
    if (ms) sqlite3_finalize(ms);
    if (tx_started) nc_exec("ROLLBACK");
    return nc_ai_history_error("storage_error", "AI history transaction was rolled back", "database");
}

int jmx_ai_history_delete(const char *actor, const char *id)
{
    sqlite3_stmt *st = NULL;

    if (!nc_ai_history_actor_ok(actor) || !nc_ai_public_id_ok(id)) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    if (nc_prepare(&st, "DELETE FROM ai_conversation WHERE id=?1 AND owner=?2") != 0 ||
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 2, actor, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        nc_step_done(st) != 0) {
        if (st) sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return nc_sqlite_changes() > 0 ? JMX_AI_HISTORY_DELETE_OK : JMX_AI_HISTORY_DELETE_NOT_FOUND;
}

int jmx_ai_history_clear(const char *actor)
{
    sqlite3_stmt *st = NULL;
    if (!nc_ai_history_actor_ok(actor) || jmx_netconfig_db_init() != 0) return -1;
    if (nc_prepare(&st, "DELETE FROM ai_conversation WHERE owner=?1") != 0) return -1;
    sqlite3_bind_text(st, 1, actor, -1, SQLITE_TRANSIENT);
    int rc = nc_step_done(st);
    sqlite3_finalize(st);
    return rc;
}

