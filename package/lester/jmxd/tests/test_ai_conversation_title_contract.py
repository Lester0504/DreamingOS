from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = (ROOT / "src/webd/ai_runtime.c").read_text()


def function_body(signature: str, *, last: bool = False) -> str:
    start = RUNTIME.rindex(signature) if last else RUNTIME.index(signature)
    brace = RUNTIME.index("{", start)
    depth = 0
    quote = None
    escaped = False
    line_comment = False
    block_comment = False
    pos = brace
    while pos < len(RUNTIME):
        ch = RUNTIME[pos]
        nxt = RUNTIME[pos + 1] if pos + 1 < len(RUNTIME) else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
            pos += 1
            continue
        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                pos += 2
            else:
                pos += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            pos += 1
            continue
        if ch == "/" and nxt == "/":
            line_comment = True
            pos += 2
            continue
        if ch == "/" and nxt == "*":
            block_comment = True
            pos += 2
            continue
        if ch in ('"', "'"):
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return RUNTIME[brace + 1 : pos]
        pos += 1
    raise AssertionError(f"unterminated function: {signature}")


def test_title_is_generated_by_the_same_provider_without_tools():
    generate = function_body("static int ai_generate_conversation_title(")
    call = function_body("static struct json_object *ai_call_chat(")

    assert "title_cfg = *cfg" in generate
    assert "ai_call_chat(&title_cfg" in generate
    assert "AI_CONVERSATION_TITLE_TOKENS" in generate
    assert "max_tokens_override > 0 ? json_object_new_array()" in call
    assert '"/messages"' in RUNTIME
    assert '"/responses"' in RUNTIME
    assert '"/chat/completions"' in RUNTIME


def test_title_is_not_a_user_text_truncation_fallback():
    finalize = function_body("static int ai_conversation_finalize(")
    normalize = function_body("static int ai_title_normalize(")

    assert "ai_chat_last_user_text" not in finalize
    assert "strndup" not in finalize
    assert "substr" not in finalize
    assert "AI_CONVERSATION_TITLE_FALLBACK" in finalize
    assert "conversation_title_generation_failed" in finalize
    assert "AI_CONVERSATION_TITLE_MAX_BYTES" in normalize


def test_existing_conversation_title_is_preserved_and_not_regenerated():
    finalize = function_body("static int ai_conversation_finalize(")
    assert 'ai_json_string(existing_item, "title"' in finalize
    assert "ai_history_has_assistant(existing_item)" in finalize
    assert "!ai_title_is_placeholder(existing_title)" in finalize
    assert 'status = "preserved"' in finalize


def test_user_only_placeholder_history_is_still_first_successful_round():
    finalize = function_body("static int ai_conversation_finalize(")

    assert "ai_title_is_placeholder(existing_title) && continuation" in finalize
    assert "ai_title_is_placeholder(existing_title) &&\n                   ai_generate_conversation_title" in finalize


def test_title_and_messages_use_the_existing_atomic_history_save():
    finalize = function_body("static int ai_conversation_finalize(")
    save = function_body("static int ai_history_save_chat(")
    history_messages = function_body("static struct json_object *ai_history_messages(")

    assert 'jmx_app_core_invoke("ai_history_get"' in RUNTIME
    assert 'jmx_app_core_invoke("ai_history_save"' in save
    assert 'json_object_object_add(request, "title"' in save
    assert 'json_object_object_add(request, "messages"' in save
    assert "ai_history_save_chat" in finalize
    assert 'json_object_new_string("assistant")' in history_messages
    assert 'json_object_new_string(reply)' in history_messages
    assert "sqlite3_open" not in save


def test_title_generation_failure_uses_a_persisted_fallback_title():
    finalize = function_body("static int ai_conversation_finalize(")
    chat = function_body("struct json_object *webd_ai_runtime_chat(")

    assert '"conversation_title"' in finalize
    assert '"history_saved"' in finalize
    assert '"title_generation"' in finalize
    assert '"degraded"' in RUNTIME
    assert '"degraded_reasons"' in RUNTIME
    assert '"conversation_title_generation_failed"' in finalize
    assert "ai_conversation_finalize(&cfg, body, data, conversation_id)" in chat
    assert "root = ai_success(data" in chat
    assert chat.index("ai_conversation_finalize") < chat.index("root = ai_success(data")
    assert "return save_ok ? 0 : -1" in finalize


def test_sensitive_material_is_redacted_and_rejected_from_titles():
    generate = function_body("static int ai_generate_conversation_title(")
    sensitive = function_body("static int ai_title_sensitive(")
    redact_prefix = function_body("static char *ai_redact_prefix(")

    assert generate.count("ai_redact_prefix(") >= 2
    assert "do not copy or reveal passwords" in generate
    for marker in ("password", "api_key", "bearer", "private key", "sk-"):
        assert marker in (generate + sensitive).lower()
    assert "\\xE5\\xAF\\x86\\xE7\\xA0\\x81" in redact_prefix
    assert "[SENSITIVE CREDENTIAL MANAGEMENT REQUEST]" in redact_prefix


def test_title_generation_remains_inside_the_concurrency_slot():
    chat = function_body("struct json_object *webd_ai_runtime_chat(")

    finalize_pos = chat.index("ai_conversation_finalize")
    close_pos = chat.index("close(slot)", finalize_pos)
    assert finalize_pos < close_pos


def test_initial_sse_persists_title_and_messages_before_completed():
    stream = function_body("int webd_ai_runtime_stream(")

    finalize = stream.index(
        "ai_conversation_finalize(&cfg, body, data, conversation_id)"
    )
    completed = stream.index('ai_stream_emit(&state, "response.completed"', finalize)
    failed = stream.index('ai_stream_emit(&state, "response.failed"', finalize)
    assert finalize < completed
    assert finalize < failed
    assert '"conversation_history_save_failed"' in stream[finalize:failed]


def test_resume_checkpoint_keeps_history_body_for_sse_completion():
    state_new = function_body("static struct json_object *ai_resume_state_new(", last=True)
    initial_stream = function_body("int webd_ai_runtime_stream(")
    resume_stream = function_body("static int ai_resume_stream_run_locked(")

    assert 'json_object_object_add(state, "history_body"' in state_new
    assert "conversation_id, actor, body, messages" in initial_stream
    assert 'json_object_object_get_ex(resume_state, "history_body"' in resume_stream
    assert "ai_conversation_finalize(&cfg, history_body, data" in resume_stream


def test_resume_sse_only_completes_and_deletes_checkpoint_after_history_save():
    resume_stream = function_body("static int ai_resume_stream_run_locked(")

    finalize = resume_stream.index(
        "ai_conversation_finalize(&cfg, history_body, data"
    )
    completed = resume_stream.index(
        'ai_stream_emit(&stream, "response.completed"', finalize
    )
    delete = resume_stream.index("ai_resume_state_delete(token)", completed)
    failure_branch = resume_stream[finalize:completed]
    assert finalize < completed < delete
    assert 'ai_stream_emit(&stream, "response.failed"' in failure_branch
    assert '"conversation_history_save_failed"' in failure_branch
    assert "ai_resume_state_delete" not in failure_branch


def test_non_stream_resume_persists_before_deleting_checkpoint_or_returning_success():
    resume = function_body("static struct json_object *ai_resume_run_locked(")

    load_history = resume.index(
        'json_object_object_get_ex(state, "history_body", &history_body)'
    )
    finalize = resume.index(
        "ai_conversation_finalize(&cfg, history_body, data"
    )
    failure = resume.index(
        'return ai_error("conversation_history_save_failed"', finalize
    )
    failure_close = resume.index("close(slot)", finalize)
    delete = resume.index("ai_resume_state_delete(token)", failure)
    success_close = resume.index("close(slot)", failure)
    success = resume.index("return ai_success(data", delete)
    assert load_history < finalize < failure < delete < success
    assert "ai_resume_state_delete" not in resume[finalize:failure]
    assert 'ai_audit(actor, "ai.tool.resume"' in resume[finalize:failure]
    assert finalize < failure_close < failure
    assert failure < success_close < delete


def test_non_stream_history_failure_returns_explicit_error_not_success():
    chat = function_body("struct json_object *webd_ai_runtime_chat(")

    finalize = chat.index("ai_conversation_finalize(&cfg, body, data, conversation_id)")
    failure = chat.index('return ai_error("conversation_history_save_failed"', finalize)
    success = chat.index("root = ai_success(data", failure)
    assert finalize < failure < success
    assert "if (http_status) *http_status = 500" in chat[finalize:failure]
