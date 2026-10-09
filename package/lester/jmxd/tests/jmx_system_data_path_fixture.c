// SPDX-License-Identifier: GPL-2.0-or-later
#include "jmx_system_data_path.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void write_file(const char *path, const char *content)
{
    FILE *file = fopen(path, "wb");

    assert(file);
    assert(fwrite(content, 1, strlen(content), file) == strlen(content));
    assert(fclose(file) == 0);
}

static int resolve(const struct jmx_system_db_paths *paths, char *selected,
                   enum jmx_system_db_source *source, char error[64])
{
    return jmx_system_db_resolve_paths(paths, selected, 512, source,
                                       error, 64);
}

int main(void)
{
    char root[] = "/tmp/jmx-system-data-path-XXXXXX";
    char hot[512];
    char runtime[512];
    char new_path[512];
    char legacy_path[512];
    char selected[512];
    char error[64];
    struct jmx_system_db_paths paths;
    enum jmx_system_db_source source;

    assert(mkdtemp(root));
    assert(snprintf(hot, sizeof(hot), "%s/hot.db", root) < (int)sizeof(hot));
    assert(snprintf(runtime, sizeof(runtime), "%s/runtime.db", root) <
           (int)sizeof(runtime));
    assert(snprintf(new_path, sizeof(new_path), "%s/new.db", root) <
           (int)sizeof(new_path));
    assert(snprintf(legacy_path, sizeof(legacy_path), "%s/legacy.db", root) <
           (int)sizeof(legacy_path));
    paths.hot = hot;
    paths.runtime = runtime;
    paths.firmware_new = new_path;
    paths.firmware_legacy = legacy_path;

    assert(resolve(&paths, selected, &source, error) != 0);
    assert(!strcmp(error, "path_not_found"));
    write_file(legacy_path, "legacy");
    assert(resolve(&paths, selected, &source, error) == 0);
    assert(source == JMX_SYSTEM_DB_SOURCE_FIRMWARE_LEGACY);
    assert(!strcmp(selected, legacy_path));

    write_file(new_path, "legacy");
    assert(resolve(&paths, selected, &source, error) == 0);
    assert(source == JMX_SYSTEM_DB_SOURCE_FIRMWARE_IDENTICAL_NEW);
    assert(!strcmp(selected, new_path));
    write_file(new_path, "conflict");
    assert(resolve(&paths, selected, &source, error) != 0);
    assert(!strcmp(error, "path_identity_conflict"));

    write_file(runtime, "runtime");
    assert(resolve(&paths, selected, &source, error) == 0);
    assert(source == JMX_SYSTEM_DB_SOURCE_RUNTIME);
    assert(!strcmp(selected, runtime));
    write_file(hot, "hot");
    assert(resolve(&paths, selected, &source, error) == 0);
    assert(source == JMX_SYSTEM_DB_SOURCE_HOT_UPDATE);
    assert(!strcmp(selected, hot));
    assert(!strcmp(jmx_system_db_source_name(source), "hot-update"));

    /* A container outranks every plaintext source; only absence falls back. */
    {
        char sealed_hot[512], sealed_runtime[512], sealed_new[512], sealed_old[512];
        snprintf(sealed_hot, sizeof(sealed_hot), "%s/hot.dwsig", root);
        snprintf(sealed_runtime, sizeof(sealed_runtime), "%s/runtime.dwsig", root);
        snprintf(sealed_new, sizeof(sealed_new), "%s/new.dwsig", root);
        snprintf(sealed_old, sizeof(sealed_old), "%s/old.dwsig", root);
        struct jmx_system_db_paths sealed = {
            sealed_hot, sealed_runtime, sealed_new, sealed_old
        };
        assert(jmx_system_signature_resolve_paths(&sealed, &paths, selected,
                   sizeof(selected), &source, error, sizeof(error)) == 0);
        assert(!strcmp(selected, hot));
        write_file(sealed_old, "container: verification belongs to loader");
        assert(jmx_system_signature_resolve_paths(&sealed, &paths, selected,
                   sizeof(selected), &source, error, sizeof(error)) == 0);
        assert(!strcmp(selected, sealed_old));
        write_file(sealed_runtime, "invalid container must not fall back");
        assert(jmx_system_signature_resolve_paths(&sealed, &paths, selected,
                   sizeof(selected), &source, error, sizeof(error)) == 0);
        assert(!strcmp(selected, sealed_runtime));
        assert(unlink(sealed_runtime) == 0);
        assert(symlink(hot, sealed_runtime) == 0);
        assert(jmx_system_signature_resolve_paths(&sealed, &paths, selected,
                   sizeof(selected), &source, error, sizeof(error)) != 0);
        assert(!strcmp(error, "path_not_safe_regular_file"));
        assert(unlink(sealed_runtime) == 0);
        assert(unlink(sealed_old) == 0);
    }

    assert(unlink(hot) == 0);
    assert(unlink(runtime) == 0);
    assert(symlink(legacy_path, runtime) == 0);
    assert(resolve(&paths, selected, &source, error) != 0);
    assert(!strcmp(error, "path_not_safe_regular_file"));
    assert(unlink(runtime) == 0);
    assert(mkdir(runtime, 0700) == 0);
    assert(resolve(&paths, selected, &source, error) != 0);
    assert(!strcmp(error, "path_not_safe_regular_file"));
    assert(rmdir(runtime) == 0);

    assert(symlink(legacy_path, hot) == 0);
    assert(resolve(&paths, selected, &source, error) != 0);
    assert(!strcmp(error, "path_not_safe_regular_file"));
    assert(unlink(hot) == 0);
    assert(unlink(new_path) == 0);
    assert(unlink(legacy_path) == 0);
    assert(rmdir(root) == 0);
    puts("ok: system database path resolver runtime fixture");
    return 0;
}
