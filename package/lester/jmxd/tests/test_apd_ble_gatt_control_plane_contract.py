#!/usr/bin/env python3
"""Static contract for the APD BLE GATT control plane (方案 A).

Pins the things that were actually broken, so a regression is loud:

  * ``apd_ble_begin_gatt_json()`` was declared in ``apd_ble.h`` with **no
    definition anywhere in the tree**.  Nothing called it, and the package
    flags carry no ``-Wall``, so unused statics and an unreferenced prototype
    both compile silently -- the entire GATT control plane was dead code that
    linked cleanly.  It is the only writer of ``physical_challenge`` and
    ``session_connection_*``, and ``apd_ble_handshake_bind()`` refuses a
    connection that has no session binding, so its absence killed DWHS too.
  * Dispatch must key on the 4-byte magic.  DWHS, DWBG and DWPC are all 54
    bytes, so a length-keyed dispatch silently hands two of the three to the
    wrong handler.
  * ``apd_ble_begin_json_ex()`` accepted any bootstrap_id, so a caller could
    make this AP open a session under another AP's identity and every layer
    would report success while the wrong device got provisioned.
"""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
APD = ROOT / "src/apd"
WEBD = ROOT / "src/webd"

HEADER = (APD / "apd_ble.h").read_text(encoding="utf-8")
BLE = (APD / "apd_ble.c").read_text(encoding="utf-8")


def macros(*texts: str) -> dict:
    """Resolve ``#define NAME <arith>`` across the given sources.

    Only integer arithmetic over other resolved macros is supported, which is
    all the wire-length constants use.  Resolving instead of hardcoding is the
    point: change APD_BLE_REQUEST_ID_LEN and the collision assertions below
    recompute and fire, rather than silently agreeing with a stale literal.
    """
    out: dict = {}
    pending: dict = {}
    for text in texts:
        joined = re.sub(r"\\\n", " ", text)
        for name, body in re.findall(
                r"^#define\s+(APD_BLE_\w+)\s+(.+)$", joined, re.M):
            body = body.split("/*")[0].strip()
            if not re.fullmatch(r"[\s\w+*()]+", body):
                continue
            pending[name] = body
    for _ in range(8):
        for name, body in pending.items():
            if name in out:
                continue
            expr = re.sub(r"\b(\d+)[Uu]\b", r"\1", body)
            try:
                out[name] = int(eval(expr, {"__builtins__": {}}, dict(out)))
            except Exception:
                continue
    return out


M = macros(HEADER, BLE)


def body(text: str, signature: str) -> str:
    """Return the brace-matched body of a definition, skipping prototypes.

    A netconfig/webd shell declares symbols ahead of the definition, so a bare
    ``index()`` lands on the prototype and then brace-matches into whatever
    function follows.  Require a ``{`` before the next ``;`` to tell the two
    apart.
    """
    for match in re.finditer(re.escape(signature), text):
        rest = text[match.end():]
        brace = rest.find("{")
        semi = rest.find(";")
        if brace < 0 or (0 <= semi < brace):
            continue                      # forward declaration, keep looking
        depth = 0
        start = match.end() + brace
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
        break
    raise AssertionError(f"no definition found for {signature!r}")


def test_begin_gatt_json_is_defined_not_just_declared() -> None:
    """The regression that made the whole control plane dead code."""
    assert "apd_ble_begin_gatt_json" in HEADER, "prototype disappeared"
    definition = body(BLE, "apd_ble_begin_gatt_json(const char *request_id")
    # It must install BOTH pieces of live state that nothing else writes.
    assert "physical_challenge_present = 1" in definition
    assert "session_connection_valid = 1" in definition
    assert "session_connection_handle = connection_handle" in definition
    # The challenge is a secret: generated locally, cleansed on the way out.
    assert "RAND_bytes(challenge" in definition
    assert "OPENSSL_cleanse(challenge" in definition
    # No identity means fail closed, never invent a bootstrap_id.
    assert "bootstrap_identity_unavailable" in definition
    # State can only be installed after begin_json_ex(), which clears it.
    ex = definition.find("apd_ble_begin_json_ex")
    install = definition.find("physical_challenge_present = 1")
    assert 0 < ex < install, "challenge installed before begin_json_ex clears it"


def test_the_54_byte_collision_forces_magic_keyed_dispatch() -> None:
    handshake = M["APD_BLE_HANDSHAKE_LEN"]
    begin = M["APD_BLE_GATT_BEGIN_LEN"]
    confirm = M["APD_BLE_GATT_PHYSICAL_CONFIRM_LEN"]
    assert handshake == begin == confirm == 54, (
        f"lengths moved: handshake={handshake} begin={begin} confirm={confirm}; "
        "the dispatch order assertion below is what protects them")

    dispatch = body(
        BLE,
        "apd_ble_gatt_control_write(const unsigned char *data, size_t len")
    # Every command is recognised by magic, and the magics come from the shared
    # header rather than being retyped as literals.
    for macro in ("APD_BLE_GATT_BEGIN_MAGIC",
                  "APD_BLE_GATT_PHYSICAL_CONFIRM_MAGIC",
                  "APD_BLE_GATT_STATUS_MAGIC",
                  "APD_BLE_GATT_COMMIT_MAGIC",
                  "APD_BLE_GATT_CANCEL_MAGIC"):
        assert f"memcmp(data, {macro}, 4)" in dispatch, macro
    # An unrecognised magic must fall through, not be guessed at.
    assert "else\n        return 0;" in dispatch


def test_control_dispatch_runs_before_the_length_test() -> None:
    """DWBG is the same 54 bytes as DWHS; order is the whole defence."""
    handler = body(BLE, "apd_ble_handle_event(const struct apd_bgapi_msg *evt")
    control = handler.find("apd_ble_gatt_control_write(data, vlen")
    length = handler.find("vlen == APD_BLE_HANDSHAKE_LEN")
    assert control > 0, "control plane not wired into the write handler"
    assert length > 0, "handshake length branch not found"
    assert control < length, (
        "length-keyed handshake branch precedes the magic dispatch, so DWBG "
        "would be handed to apd_ble_handshake_bind()")


def test_begin_response_wire_shape() -> None:
    header_len = M["APD_BLE_GATT_RESPONSE_HEADER_LEN"]
    assert header_len == 8, "magic4 + version1 + command1 + status2"
    assert M["APD_BLE_GATT_BEGIN_RESPONSE_LEN"] == 160
    assert M["APD_BLE_GATT_ACTION_LEN"] == 22
    assert M["APD_BLE_GATT_ACTION_RESPONSE_LEN"] == 24
    assert M["APD_BLE_GATT_STATUS_RESPONSE_LEN"] == 34

    payload = body(
        BLE, "apd_ble_gatt_begin_payload(struct json_object *result")
    # 152 = 160 - 8: the builder returns payload only: the 8-byte header is
    # added by apd_ble_send_gatt_response().  Derived from the macros, not
    # retyped, so the two can never drift apart.
    assert M["APD_BLE_GATT_BEGIN_RESPONSE_LEN"] - header_len == 152
    assert ("APD_BLE_GATT_BEGIN_RESPONSE_LEN -\n"
            "                  APD_BLE_GATT_RESPONSE_HEADER_LEN") in payload
    assert "out_size < need" in payload, "must refuse an undersized buffer"
    assert "return (int)need;" in payload

    # Wire layout, read from the writes that actually advance the offset.
    steps = re.findall(
        r"(?:offset = |offset \+= )(APD_BLE_\w+)|"
        r"(apd_ble_uuid_parse|apd_ble_hex_decode|memcpy|apd_ble_put_u64_be)",
        payload)
    writes = [a or b for a, b in steps]
    assert writes == [
        "apd_ble_hex_decode",                        # session_id  16
        "APD_BLE_SESSION_ID_LEN",
        "apd_ble_uuid_parse",                        # bootstrap_id 16
        "APD_BLE_REQUEST_ID_LEN",
        "apd_ble_uuid_parse",                        # request_id   16
        "APD_BLE_REQUEST_ID_LEN",
        "apd_ble_hex_decode",                        # public_key   32
        "APD_BLE_X25519_KEY_LEN",
        "apd_ble_hex_decode",                        # nonce        32
        "APD_BLE_BOOTSTRAP_NONCE_LEN",
        "memcpy",                                    # challenge    32
        "APD_BLE_GATT_BEGIN_RESPONSE_CHALLENGE_LEN",
        "apd_ble_put_u64_be",                        # expires_at    8
    ], writes
    for field in ('"session_id"', '"bootstrap_id"', '"request_id"',
                  '"public_key"', '"bootstrap_nonce"', '"expires_at"'):
        assert field in payload, field


def test_challenge_comes_from_live_state_not_from_json() -> None:
    """It is the physical-presence secret for this BLE link."""
    payload = body(
        BLE, "apd_ble_gatt_begin_payload(struct json_object *result")
    assert "g_apd_ble.physical_challenge" in payload
    assert "physical_challenge_present" in payload
    assert "pthread_mutex_lock(&g_apd_ble.lock)" in payload
    # Never read a field named challenge out of the JSON result.
    assert 'apd_ble_json_string(result, "challenge"' not in payload


def test_physical_confirm_checks_a_present_flag_not_a_zero_challenge() -> None:
    confirm = body(BLE, "apd_ble_gatt_physical_confirm(const unsigned char *data")
    assert "challenge_present" in confirm, "explicit presence flag required"
    # A 32-byte random challenge can legitimately start with zero bytes, so
    # inferring presence from the first bytes rejects a valid confirm.
    assert "!challenge[0] && !challenge[1]" not in confirm
    assert "OPENSSL_cleanse" in confirm


def test_actions_are_bound_to_the_session_connection() -> None:
    dispatch = body(
        BLE,
        "apd_ble_gatt_control_write(const unsigned char *data, size_t len")
    assert "apd_ble_gatt_session_allowed(connection, session_id)" in dispatch
    assert "apd_ble_current_connection(connection)" in dispatch
    assert "APD_BLE_GATT_STATUS_TARGET_MISMATCH" in dispatch
    allowed = body(BLE, "apd_ble_gatt_session_allowed(uint8_t connection")
    assert "session_connection_valid" in allowed
    assert "session_connection_handle" in allowed


def test_begin_refuses_another_aps_bootstrap_id() -> None:
    """Covers the ubus/HTTP path too: apd_ubus.c calls begin_json_ex()."""
    begin_ex = body(BLE, "apd_ble_begin_json_ex(const char *bootstrap_id")
    assert "own_bootstrap_id" in begin_ex
    assert "apd_ble_bootstrap_id_get(own_bootstrap_id)" in begin_ex
    assert "strcasecmp(own_bootstrap_id, bootstrap_id)" in begin_ex
    assert 'apd_ble_error("target_ap_mismatch")' in begin_ex
    assert 'apd_ble_error("bootstrap_identity_unavailable")' in begin_ex
    # The check must precede session creation, or the wrong session already
    # exists by the time we reject.
    check = begin_ex.find("strcasecmp(own_bootstrap_id")
    create = begin_ex.find("apd_ble_db_begin")
    if create > 0:
        assert check < create, "mismatch check runs after the session is created"
    ubus = (APD / "apd_ubus.c").read_text(encoding="utf-8")
    assert "apd_ble_begin_json_ex" in ubus, "HTTP path must share the guard"


def test_att_status_mapping_is_total() -> None:
    mapping = body(
        BLE, "apd_ble_att_status_for_gatt_status(unsigned short status)")
    for macro in ("APD_BLE_GATT_RESPONSE_OK",
                  "APD_BLE_GATT_STATUS_INVALID_ARGUMENT",
                  "APD_BLE_GATT_STATUS_TARGET_MISMATCH",
                  "APD_BLE_GATT_STATUS_PHYSICAL_AUTH_REQUIRED",
                  "APD_BLE_GATT_STATUS_SETUP_CODE_INVALID",
                  "APD_BLE_GATT_STATUS_SESSION_NOT_FOUND",
                  "APD_BLE_GATT_STATUS_SESSION_EXPIRED"):
        assert macro in mapping, macro
    assert "default:" in mapping, "unmapped status must not fall through"


def test_response_is_always_sent_and_never_rewrites_att_status() -> None:
    dispatch = body(
        BLE,
        "apd_ble_gatt_control_write(const unsigned char *data, size_t len")
    assert "respond:" in dispatch, "single response path required"
    send = dispatch.find("apd_ble_send_gatt_response(connection, command")
    assert send > 0
    # A failed notification is logged, not turned into an ATT error: the app
    # already has the status byte from the write response.
    assert dispatch.find("*att_status =", dispatch.find("respond:")) < send
    assert "apd_ble_events_connection(connection)" in dispatch
    assert "OPENSSL_cleanse(payload" in dispatch
    assert dispatch.rstrip().endswith("return 1;\n}")


def test_webd_bridge_maps_the_new_codes() -> None:
    bridge = (WEBD / "api/api_ble_provision.c").read_text(encoding="utf-8")
    status = body(bridge, "ble_error_status(const char *code)")

    def group(code: str) -> int:
        at = status.find(f'"{code}"')
        assert at > 0, f"{code} unmapped"
        tail = status[at:]
        found = re.search(r"return (\d+);", tail)
        assert found, code
        return int(found.group(1))

    assert group("target_ap_mismatch") == 409
    assert group("bootstrap_identity_unavailable") == 503
    assert group("target_ap_unreachable") == 503
    assert group("session_not_found") == 404

    # An absent apd means the requested AP is not reachable from this host --
    # there is no AP-to-AP relay -- so the app's next move is BLE, not a retry.
    response = body(bridge, "ble_response(struct jmx_api_ctx *ctx")
    absent = response[response.find("if (!upstream)"):]
    assert '"target_ap_unreachable"' in absent[:600]
    assert '"source_unavailable"' not in absent[:600]


def test_previously_dead_helpers_now_have_callers() -> None:
    """Seven functions had zero callers; no -Wall means nothing said so."""
    for name in ("apd_ble_send_gatt_response", "apd_ble_gatt_action_parse",
                 "apd_ble_gatt_result_status", "apd_ble_gatt_flags_locked",
                 "apd_ble_gatt_physical_confirm", "apd_ble_uuid_format",
                 "apd_ble_events_connection"):
        uses = len(re.findall(rf"\b{name}\s*\(", BLE))
        assert uses >= 2, (
            f"{name} appears {uses}x -- definition only, still dead code")


if __name__ == "__main__":
    test_begin_gatt_json_is_defined_not_just_declared()
    test_the_54_byte_collision_forces_magic_keyed_dispatch()
    test_control_dispatch_runs_before_the_length_test()
    test_begin_response_wire_shape()
    test_challenge_comes_from_live_state_not_from_json()
    test_physical_confirm_checks_a_present_flag_not_a_zero_challenge()
    test_actions_are_bound_to_the_session_connection()
    test_begin_refuses_another_aps_bootstrap_id()
    test_att_status_mapping_is_total()
    test_response_is_always_sent_and_never_rewrites_att_status()
    test_webd_bridge_maps_the_new_codes()
    test_previously_dead_helpers_now_have_callers()
    print("ok: APD BLE GATT control plane contract")
