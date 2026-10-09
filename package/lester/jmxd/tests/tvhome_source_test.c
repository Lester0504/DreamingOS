// SPDX-License-Identifier: GPL-2.0-or-later
/* Exercise the real C source/import paths with deterministic helper outcomes. */
#include "tvhome/tvhome_packages.h"
#include "tvhome/tvhome_assets.h"
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#if !defined(TVH_DB_PATH) || !defined(TVHOME_APK_HELPER)
#error Disposable database and helper paths required
#endif
static int checks;
static char disk[] = "/tmp/tvhome-source-disk-XXXXXX";
#define CHECK(c) do { checks++; if (!(c)) { fprintf(stderr, "FAIL %d: %s [%d %s]\n", __LINE__, #c, e.http_status, e.code); exit(1); } } while (0)
int tvhome_ws_count(const char *id) { (void)id; return 0; }
int storage_files_open_dir(const char *root, const char *path, int write,
                          char *canonical, size_t size, const char **reason)
{
    (void)path; (void)write;
    if (strcmp(root, "source-test")) { *reason = "unknown_root"; return -1; }
    snprintf(canonical, size, "%s", disk);
    return open(disk, O_RDONLY | O_DIRECTORY);
}
int main(void)
{
    struct tvhome_err e = {0};
    CHECK(!strncmp(TVH_DB_PATH, "/tmp/", 5) && !strncmp(TVHOME_APK_HELPER, "/tmp/", 5));
    CHECK(mkdtemp(disk));
    unlink(TVH_DB_PATH);
    FILE *f = fopen(TVHOME_APK_HELPER, "w");
    CHECK(f);
    fputs("#!/bin/sh\n"
          "case \"$1\" in\n"
          " source) case \"$TVHOME_SOURCE_CASE\" in\n"
          "  legacy) exit 1;;\n"
          "  unavailable) exit 3;;\n"
          "  invalid) echo 'invalid JSON';;\n"
          "  empty) echo '{\"latest\":null}';;\n"
          "  *) echo '{\"latest\":{\"id\":\"test-release\",\"version\":\"1.0\",\"size\":1}}';;\n"
          " esac;;\n"
          " import) [ \"$TVHOME_SOURCE_CASE\" = apk ] && exit 1; exit 3;;\n"
          " *) exit 1;;\n"
          "esac\n", f);
    CHECK(!fclose(f) && !chmod(TVHOME_APK_HELPER, 0700));
    struct json_object *r = tvhome_release_source("phone", &e);
    CHECK(!r && e.http_status == 400 && !strcmp(e.code, "invalid_parameter"));
    const char *failures[] = {"legacy", "unavailable", "invalid"};
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); i++) {
        CHECK(!setenv("TVHOME_SOURCE_CASE", failures[i], 1));
        r = tvhome_release_source("stable", &e);
        CHECK(!r && e.http_status == 502 && !strcmp(e.code, "release_source_unavailable"));
    }
    CHECK(!setenv("TVHOME_SOURCE_CASE", "empty", 1));
    r = tvhome_release_source("beta", &e);
    CHECK(r && !tv_get(r, "latest"));
    json_object_put(r);
    r = tvhome_release_import("beta", &e);
    CHECK(!r && e.http_status == 404 && !strcmp(e.code, "release_unavailable"));
    struct json_object *b = json_tokener_parse("{\"root_id\":\"source-test\",\"path\":\"\"}");
    r = tvhome_assets_storage(b, &e);
    CHECK(r);
    json_object_put(b); json_object_put(r);
    CHECK(!setenv("TVHOME_SOURCE_CASE", "download", 1));
    r = tvhome_release_import("stable", &e);
    CHECK(!r && e.http_status == 502 && !strcmp(e.code, "release_source_unavailable"));
    CHECK(!setenv("TVHOME_SOURCE_CASE", "apk", 1));
    r = tvhome_release_import("stable", &e);
    CHECK(!r && e.http_status == 400 && !strcmp(e.code, "apk_verification_failed"));
    r = tvhome_packages_get(NULL, &e);
    CHECK(r && json_object_array_length(tv_get(r, "packages")) == 0);
    json_object_put(r);
    char assets[256];
    snprintf(assets, sizeof(assets), "%s/.dreaming-tvhome", disk);
    CHECK(!rmdir(assets));
    CHECK(!rmdir(disk));
    unlink(TVH_DB_PATH); unlink(TVHOME_APK_HELPER);
    printf("PASS %d checks: source errors, empty channel, import failure classification and cleanup\n", checks);
    return 0;
}
