// SPDX-License-Identifier: GPL-2.0-or-later
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "webd/ai_oauth.h"

#define TEST_STATE_DIR "/tmp/dreamingwrt-ai-oauth-openai-test"

static int fail(const char *message)
{
    fprintf(stderr, "openai oauth live contract: %s\n", message);
    return 1;
}

static const char *string_field(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v) && v &&
           json_object_is_type(v, json_type_string) ?
           json_object_get_string(v) : NULL;
}

static int bool_field(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v) && v &&
           json_object_get_boolean(v);
}

static int response_has_secret(struct json_object *response)
{
    const char *text = json_object_to_json_string_ext(
        response, JSON_C_TO_STRING_PLAIN);
    return text && (strstr(text, "access_token") ||
                    strstr(text, "refresh_token") ||
                    strstr(text, "code_verifier") ||
                    strstr(text, "device_code"));
}

static int pending_file_is_encrypted(void)
{
    char path[256], buf[4096];
    struct stat st;
    ssize_t got;
    int fd;

    snprintf(path, sizeof(path), "%s/openai.pending.enc", TEST_STATE_DIR);
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & 077)) {
        if (fd >= 0) close(fd);
        return 0;
    }
    got = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (got < 5) return 0;
    buf[got] = 0;
    return !memcmp(buf, "DWAO1", 5) && !strstr(buf, "code_verifier") &&
           !strstr(buf, "access_token") && !strstr(buf, "refresh_token");
}

int main(void)
{
    struct json_object *catalog = NULL, *providers = NULL, *openai = NULL;
    struct json_object *request = NULL, *start = NULL, *status_obj = NULL;
    struct json_object *callback = NULL, *result = NULL, *disconnect = NULL;
    const char *url, *state;
    int status = 0;

    if (system("rm -rf " TEST_STATE_DIR) != 0)
        return fail("could not reset test state directory");
    catalog = webd_ai_oauth_catalog();
    if (!catalog || !json_object_object_get_ex(catalog, "providers", &providers) ||
        !providers || !json_object_is_type(providers, json_type_array))
        return fail("catalog missing providers");
    for (size_t i = 0; i < json_object_array_length(providers); i++) {
        struct json_object *item = json_object_array_get_idx(providers, i);
        if (!strcmp(string_field(item, "provider") ?: "", "openai")) {
            openai = item;
            break;
        }
    }
    if (!openai || !bool_field(openai, "supported") ||
        strcmp(string_field(openai, "mode") ?: "",
               "chatgpt_authorization_code_pkce_s256") ||
        strcmp(string_field(openai, "account_type") ?: "", "chatgpt_oauth") ||
        strcmp(string_field(openai, "api_key_account_type") ?: "", "api_key") ||
        strcmp(string_field(openai, "callback_transport") ?: "",
               "manual_callback_url_to_poll") ||
        !bool_field(openai, "callback_url_parse_required") ||
        bool_field(openai, "custom_redirect_uri_supported"))
        return fail("OpenAI catalog contract mismatch");

    request = json_object_new_object();
    json_object_object_add(request, "provider", json_object_new_string("openai"));
    json_object_object_add(request, "redirect_uri",
                           json_object_new_string("https://router.invalid/callback"));
    start = webd_ai_oauth_start(request, "contract-admin", &status);
    if (status != 400 || strcmp(string_field(start, "error") ?: "",
                                "invalid_oauth_request"))
        return fail("custom OpenAI redirect URI was not rejected");
    json_object_put(start);
    start = NULL;
    json_object_object_del(request, "redirect_uri");
    start = webd_ai_oauth_start(request, "contract-admin", &status);
    url = string_field(start, "authorization_url");
    state = string_field(start, "state");
    if (status != 200 || !bool_field(start, "ok") || !url || !state ||
        !strstr(url, "https://auth.openai.com/oauth/authorize?") ||
        !strstr(url, "client_id=app_EMoamEEZ73f0CkXaXp7hrann") ||
        !strstr(url, "redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback") ||
        !strstr(url, "scope=openid%20profile%20email%20offline_access") ||
        !strstr(url, "code_challenge_method=S256") ||
        !strstr(url, "id_token_add_organizations=true") ||
        !strstr(url, "codex_cli_simplified_flow=true") ||
        strcmp(string_field(start, "callback_transport") ?: "",
               "manual_callback_url_to_poll") ||
        !bool_field(start, "callback_url_parse_required") ||
        response_has_secret(start))
        return fail("authorization start contract mismatch");
    if (!pending_file_is_encrypted())
        return fail("pending state is not encrypted root-only storage");

    status_obj = webd_ai_oauth_status("openai", &status);
    if (status != 200 || bool_field(status_obj, "connected") ||
        !bool_field(status_obj, "pending") || response_has_secret(status_obj))
        return fail("pending status contract mismatch");

    callback = json_object_new_object();
    json_object_object_add(callback, "provider", json_object_new_string("openai"));
    json_object_object_add(callback, "callback_url", json_object_new_string(
        "http://router.invalid:1455/auth/callback?code=not-exchanged&state=wrong"));
    result = webd_ai_oauth_poll(callback, "contract-admin", &status);
    if (status != 400 || strcmp(string_field(result, "error") ?: "",
                                "invalid_oauth_callback") || response_has_secret(result))
        return fail("unregistered callback URL was not rejected");
    json_object_put(result);
    result = NULL;
    json_object_object_del(callback, "callback_url");
    json_object_object_add(callback, "callback_url", json_object_new_string(
        "http://localhost:1455/auth/callback?code=first&code=second&state=wrong"));
    result = webd_ai_oauth_poll(callback, "contract-admin", &status);
    if (status != 400 || strcmp(string_field(result, "error") ?: "",
                                "invalid_oauth_callback") || response_has_secret(result))
        return fail("duplicate callback parameter was not rejected");
    json_object_put(result);
    result = NULL;
    json_object_object_del(callback, "callback_url");
    json_object_object_add(callback, "callback_url", json_object_new_string(
        "http://localhost:1455/auth/callback?code=%00&state=wrong"));
    result = webd_ai_oauth_poll(callback, "contract-admin", &status);
    if (status != 400 || strcmp(string_field(result, "error") ?: "",
                                "invalid_oauth_callback") || response_has_secret(result))
        return fail("NUL callback value was not rejected");
    json_object_put(result);
    result = NULL;
    json_object_object_del(callback, "callback_url");
    json_object_object_add(callback, "callback_url", json_object_new_string(
        "http://localhost:1455/auth/callback?code=%ZZ&state=wrong"));
    result = webd_ai_oauth_poll(callback, "contract-admin", &status);
    if (status != 400 || strcmp(string_field(result, "error") ?: "",
                                "invalid_oauth_callback") || response_has_secret(result))
        return fail("invalid percent encoding was not rejected");
    json_object_put(result);
    result = NULL;
    json_object_object_del(callback, "callback_url");
    json_object_object_add(callback, "code", json_object_new_string("not-exchanged"));
    json_object_object_add(callback, "state", json_object_new_string(state));
    result = webd_ai_oauth_poll(callback, "different-actor", &status);
    if (status != 403 || strcmp(string_field(result, "error") ?: "",
                                "oauth_actor_mismatch") || response_has_secret(result))
        return fail("actor binding contract mismatch");
    json_object_put(result);
    result = NULL;
    json_object_object_del(callback, "code");
    json_object_object_del(callback, "state");
    json_object_object_add(callback, "callback_url", json_object_new_string(
        "http://localhost:1455/auth/callback?code=not%2Dexchanged&state=wrong%2Dstate"));
    result = webd_ai_oauth_poll(callback, "contract-admin", &status);
    if (status != 400 || strcmp(string_field(result, "error") ?: "",
                                "oauth_state_mismatch") || response_has_secret(result))
        return fail("state validation contract mismatch");

    disconnect = webd_ai_oauth_disconnect("openai", "contract-admin", &status);
    if (status != 200 || !bool_field(disconnect, "ok") ||
        bool_field(disconnect, "connected") || response_has_secret(disconnect) ||
        access(TEST_STATE_DIR "/openai.pending.enc", F_OK) == 0 ||
        access(TEST_STATE_DIR "/openai.in-flight.enc", F_OK) == 0 ||
        access(TEST_STATE_DIR "/openai.token.enc", F_OK) == 0)
        return fail("disconnect cleanup contract mismatch");

    json_object_put(disconnect);
    json_object_put(result);
    json_object_put(callback);
    json_object_put(status_obj);
    json_object_put(start);
    json_object_put(request);
    json_object_put(catalog);
    if (system("rm -rf " TEST_STATE_DIR) != 0)
        return fail("could not clean test state directory");
    puts("openai oauth live contract: ok");
    return 0;
}
