// SPDX-License-Identifier: GPL-2.0-or-later
#include "otad/otad_persist_source.h"

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

static int has_prefix(const struct otad_persist_prefixes *prefixes,
                      const char *expected)
{
    size_t i;

    for (i = 0; i < prefixes->count; i++)
        if (!strcmp(prefixes->items[i], expected))
            return 1;
    return 0;
}

int main(void)
{
    char root[] = "/tmp/otad-persist-source-XXXXXX";
    char new_dir[256];
    char legacy_dir[256];
    char runtime_dir[256];
    char path[320];
    struct otad_persist_prefixes prefixes;
    struct otad_persist_source_status status;

    assert(mkdtemp(root));
    assert(snprintf(new_dir, sizeof(new_dir), "%s/new", root) <
           (int)sizeof(new_dir));
    assert(snprintf(legacy_dir, sizeof(legacy_dir), "%s/legacy", root) <
           (int)sizeof(legacy_dir));
    assert(snprintf(runtime_dir, sizeof(runtime_dir), "%s/runtime", root) <
           (int)sizeof(runtime_dir));
    assert(mkdir(new_dir, 0700) == 0);
    assert(mkdir(legacy_dir, 0700) == 0);
    assert(mkdir(runtime_dir, 0700) == 0);

    assert(otad_persist_sources_load(new_dir, legacy_dir, runtime_dir,
                                     &prefixes, &status) == 0);
    assert(prefixes.count == 0);
    otad_persist_prefixes_free(&prefixes);

    assert(snprintf(path, sizeof(path), "%s/new.list", new_dir) <
           (int)sizeof(path));
    write_file(path, "# new\n/new-only\n/shared\n");
    assert(snprintf(path, sizeof(path), "%s/legacy.list", legacy_dir) <
           (int)sizeof(path));
    write_file(path, "/legacy-only\n/shared\n");
    assert(snprintf(path, sizeof(path), "%s/same.list", new_dir) <
           (int)sizeof(path));
    write_file(path, "/identical\n");
    assert(snprintf(path, sizeof(path), "%s/same.list", legacy_dir) <
           (int)sizeof(path));
    write_file(path, "/identical\n");
    assert(snprintf(path, sizeof(path), "%s/runtime.list", runtime_dir) <
           (int)sizeof(path));
    write_file(path, "/runtime-authority\n/shared\n");

    assert(otad_persist_sources_load(new_dir, legacy_dir, runtime_dir,
                                     &prefixes, &status) == 0);
    assert(status.new_only == 1);
    assert(status.legacy_only == 1);
    assert(status.identical_new == 1);
    assert(status.runtime_files == 1);
    assert(prefixes.count == 5);
    assert(has_prefix(&prefixes, "/new-only"));
    assert(has_prefix(&prefixes, "/legacy-only"));
    assert(has_prefix(&prefixes, "/identical"));
    assert(has_prefix(&prefixes, "/runtime-authority"));
    assert(has_prefix(&prefixes, "/shared"));
    otad_persist_prefixes_free(&prefixes);

    assert(snprintf(path, sizeof(path), "%s/same.list", legacy_dir) <
           (int)sizeof(path));
    write_file(path, "/conflict\n");
    assert(otad_persist_sources_load(new_dir, legacy_dir, runtime_dir,
                                     &prefixes, &status) != 0);
    assert(!strcmp(status.error, "path_identity_conflict"));
    assert(prefixes.count == 0);
    assert(unlink(path) == 0);

    assert(snprintf(path, sizeof(path), "%s/link.list", legacy_dir) <
           (int)sizeof(path));
    assert(symlink("legacy.list", path) == 0);
    assert(otad_persist_sources_load(new_dir, legacy_dir, runtime_dir,
                                     &prefixes, &status) != 0);
    assert(!strcmp(status.error, "path_not_safe_regular_file"));
    assert(prefixes.count == 0);
    assert(unlink(path) == 0);

    assert(snprintf(path, sizeof(path), "%s/runtime.list", runtime_dir) <
           (int)sizeof(path));
    write_file(path, "relative/path\n");
    assert(otad_persist_sources_load(new_dir, legacy_dir, runtime_dir,
                                     &prefixes, &status) != 0);
    assert(!strcmp(status.error, "runtime_persist_list_read_failed"));
    assert(prefixes.count == 0);

    assert(unlink(path) == 0);
    assert(snprintf(path, sizeof(path), "%s/new.list", new_dir) <
           (int)sizeof(path));
    assert(unlink(path) == 0);
    assert(snprintf(path, sizeof(path), "%s/legacy.list", legacy_dir) <
           (int)sizeof(path));
    assert(unlink(path) == 0);
    assert(snprintf(path, sizeof(path), "%s/same.list", new_dir) <
           (int)sizeof(path));
    assert(unlink(path) == 0);
    assert(rmdir(runtime_dir) == 0);
    assert(rmdir(legacy_dir) == 0);
    assert(rmdir(new_dir) == 0);
    assert(rmdir(root) == 0);
    puts("ok: otad persist source runtime fixture");
    return 0;
}
