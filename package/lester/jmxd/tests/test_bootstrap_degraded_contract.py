#!/usr/bin/env python3
"""A degraded bootstrap must be machine-detectable and must not claim jmxd data.

`GET /api/v1/bootstrap` answered 200 with `ok:true` while the capability source
was unreachable. The payload was not empty -- the keys
`webd_apply_runtime_capabilities()` writes locally survive -- so the response
carried 13 capability keys instead of 192, and `realtime_ws` was *absent* rather
than false because it is added inside the success branch of
`webd_capabilities_data_fast()`. A client could not tell "not confirmed" from
"explicitly unsupported" except by reading `backend.jmxd_online`.

Measured on 30.1 after `dreamingwrt-init restart core`: 38 consecutive degraded
responses before the first healthy reply, followed by another dip. That is not
a simple fixed-duration startup window: a later steady-state sample still saw
12 degraded replies out of 30 because core's single-threaded dispatch can take
seconds (`capabilities` up to 3.5s, `setup_status` up to 2.7s) while webd budgets
250ms. Every degraded reply used to say `meta.source = "webd+jmxd"`.

Three things are pinned here.

1. `meta.source` reflects whether jmxd actually answered. The old expression
   `(caps || setup) ? "webd+jmxd" : "webd"` could never be false, because `caps`
   is replaced with an empty object before it is tested.
2. The degradation is announced at the top level, and each source reports its
   own availability. `jmxd_online` is an OR, so it stays true when only setup
   failed -- a partial case observed live on 30.1.
3. A degraded payload is never cached. The guest entry lives 10s, so caching a
   momentary miss would manufacture a deterministic 10s outage.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text, webd_function_text
WEBD = webd_dispatch_text()


def bootstrap_body() -> str:
    return webd_function_text("api_bootstrap.c", "webd_bootstrap_response")


def test_meta_source_is_not_a_constant_claim_of_jmxd_data() -> None:
    body = bootstrap_body()
    assert 'webd_envelope(data, (caps_available && setup_available) ? "webd+jmxd" : "webd")' in body, (
        "meta.source is not derived from whether jmxd answered")
    assert 'webd_envelope(data, (caps || setup) ? "webd+jmxd" : "webd")' not in body, (
        "meta.source still tests the caps pointer, which is replaced with an "
        "empty object above and so is never NULL -- the response would keep "
        "claiming jmxd data when jmxd answered nothing")
    # The pointer really is unconditionally non-NULL before that point.
    assert "if (!caps)\n        caps = json_object_new_object();" in body, (
        "the empty-object fallback moved; re-check whether the source expression "
        "can now distinguish a failed lookup on its own")


def test_degradation_is_announced_at_the_top_level() -> None:
    body = bootstrap_body()
    assert 'json_object_object_add(resp, "degraded", json_object_new_boolean(1))' in body, (
        "a degraded response is not flagged; the client can only infer it by "
        "reading backend.jmxd_online or noticing a missing key")
    for reason in ("capabilities_and_setup_source_unavailable",
                   "capabilities_source_unavailable",
                   "setup_source_unavailable"):
        assert f'"{reason}"' in body, f"{reason} is not reported"
    at = body.index('"degraded"')
    guard = body[max(0, at - 260):at]
    assert "!caps_available || !setup_available" in guard, (
        "the degraded flag is not gated on source availability, so a healthy "
        "response would advertise itself as degraded")


def test_each_source_reports_its_own_availability() -> None:
    """jmxd_online is an OR: setup can fail while it still reads true."""
    body = bootstrap_body()
    assert 'json_object_new_boolean(caps_available || setup_available)' in body, (
        "jmxd_online no longer an OR; the per-source flags below assume it is")
    assert '"capabilities_available", json_object_new_boolean(caps_available)' in body, (
        "capabilities availability is not reported separately, so a client "
        "testing jmxd_online misses a capabilities-only failure")
    assert '"setup_available", json_object_new_boolean(setup_available)' in body, (
        "setup availability is not reported separately")


def test_unconfirmed_capabilities_are_null_not_absent() -> None:
    """Absent and false are indistinguishable to a client that reads the map."""
    body = bootstrap_body()
    assert "if (!caps_available) {" in body, (
        "nothing marks the capability map as unconfirmed")
    at = body.index("if (!caps_available) {")
    block = body[at:at + 1400]
    for key in ("realtime_ws", "realtime_websocket", "realtime_topics"):
        assert f'"{key}"' in block, (
            f"{key} is not reported as unconfirmed; it vanishes from a degraded "
            f"payload and reads as 'not advertised'")
    assert "json_object_object_add(caps, unconfirmed[i], NULL)" in block, (
        "unconfirmed capabilities are not set to null, so 'unknown' stays "
        "indistinguishable from 'unsupported'")
    assert "struct json_object *existing = NULL" in block and \
           "json_object_object_get_ex(caps, unconfirmed[i], &existing)" in block, (
        "the null fill is unconditional and would overwrite a value that the "
        "local runtime pass legitimately determined")


def test_a_degraded_payload_is_never_cached() -> None:
    body = bootstrap_body()
    assert "if (guest_bootstrap && caps_available && setup_available)" in body, (
        "a degraded response can still be cached; the guest entry would turn a "
        "momentary source miss into stale 'unknown' for every guest for 10s")
    at = body.index('jmx_cache_put("webd_bootstrap:guest"')
    assert "caps_available && setup_available" in body[max(0, at - 400):at], (
        "the cache write is not guarded by source availability")


def test_bootstrap_does_not_fetch_setup_twice() -> None:
    body = bootstrap_body()
    assert body.count("webd_setup_data_fast(&setup_available)") == 1, (
        "bootstrap no longer has exactly one authoritative setup fetch")
    assert "webd_apply_runtime_capabilities_with_setup(caps, hide_funcs, disabled_caps," in body, (
        "bootstrap does not pass its setup result into the runtime overlay; the "
        "overlay would call setup_status again when core is already timing out")
    helper_start = WEBD.index(
        "static void webd_apply_runtime_capabilities_with_setup(")
    wrapper_start = WEBD.index(
        "static void webd_apply_runtime_capabilities(", helper_start)
    helper = WEBD[helper_start:wrapper_start]
    assert "webd_setup_data_fast" not in helper, (
        "the borrowed-setup helper still fetches setup on its own")
    assert "json_object_put(setup)" not in helper, (
        "the borrowed-setup helper consumes an object still owned by bootstrap")


if __name__ == "__main__":
    test_meta_source_is_not_a_constant_claim_of_jmxd_data()
    test_degradation_is_announced_at_the_top_level()
    test_each_source_reports_its_own_availability()
    test_unconfirmed_capabilities_are_null_not_absent()
    test_a_degraded_payload_is_never_cached()
    test_bootstrap_does_not_fetch_setup_twice()
    print("ok: a degraded bootstrap is flagged, per-source, null-marked, "
          "uncached, and does not claim jmxd data")
