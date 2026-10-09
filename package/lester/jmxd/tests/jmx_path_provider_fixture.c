// SPDX-License-Identifier: GPL-2.0-or-later
#include "jmx_path_provider.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
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

static int select_path(const char *new_path, const char *legacy_path,
                       char *selected, size_t selected_len,
                       enum jmx_path_selection *selection, char error[64])
{
    return jmx_path_select_immutable(new_path, legacy_path, selected,
                                     selected_len, selection, error, 64);
}

int main(void)
{
    char root[] = "/tmp/jmx-path-provider-XXXXXX";
    char new_path[256];
    char legacy_path[256];
    char directory_path[256];
    char new_dir[256];
    char legacy_dir[256];
    char file_path[256];
    char selected[256];
    char error[64];
    enum jmx_path_selection selection;
    struct jmx_immutable_file_set set;

    assert(mkdtemp(root));
    assert(snprintf(new_path, sizeof(new_path), "%s/new.db", root) <
           (int)sizeof(new_path));
    assert(snprintf(legacy_path, sizeof(legacy_path), "%s/legacy.db", root) <
           (int)sizeof(legacy_path));
    assert(snprintf(directory_path, sizeof(directory_path), "%s/directory", root) <
           (int)sizeof(directory_path));
    assert(snprintf(new_dir, sizeof(new_dir), "%s/new-dir", root) <
           (int)sizeof(new_dir));
    assert(snprintf(legacy_dir, sizeof(legacy_dir), "%s/legacy-dir", root) <
           (int)sizeof(legacy_dir));

    assert(select_path(new_path, legacy_path, selected, sizeof(selected),
                       &selection, error) != 0);
    assert(!strcmp(error, "path_not_found"));
    assert(selection == JMX_PATH_SELECTION_NONE);

    write_file(legacy_path, "legacy");
    assert(select_path(new_path, legacy_path, selected, sizeof(selected),
                       &selection, error) == 0);
    assert(!strcmp(selected, legacy_path));
    assert(selection == JMX_PATH_SELECTION_LEGACY);
    assert(!strcmp(jmx_path_selection_name(selection), "legacy-fallback"));

    write_file(new_path, "legacy");
    assert(select_path(new_path, legacy_path, selected, sizeof(selected),
                       &selection, error) == 0);
    assert(!strcmp(selected, new_path));
    assert(selection == JMX_PATH_SELECTION_IDENTICAL_NEW);

    write_file(new_path, "different");
    assert(select_path(new_path, legacy_path, selected, sizeof(selected),
                       &selection, error) != 0);
    assert(!strcmp(error, "path_identity_conflict"));
    assert(selected[0] == '\0');

    assert(unlink(new_path) == 0);
    assert(select_path(new_path, legacy_path, selected, sizeof(selected),
                       &selection, error) == 0);
    assert(selection == JMX_PATH_SELECTION_LEGACY);
    assert(unlink(legacy_path) == 0);
    write_file(new_path, "new-only");
    assert(select_path(new_path, legacy_path, selected, sizeof(selected),
                       &selection, error) == 0);
    assert(selection == JMX_PATH_SELECTION_NEW);
    assert(!strcmp(jmx_path_selection_name(selection), "new-only"));

    assert(symlink(new_path, legacy_path) == 0);
    assert(select_path(new_path, legacy_path, selected, sizeof(selected),
                       &selection, error) != 0);
    assert(!strcmp(error, "path_not_safe_regular_file"));
    assert(unlink(legacy_path) == 0);
    assert(mkdir(directory_path, 0700) == 0);
    assert(select_path(directory_path, new_path, selected, sizeof(selected),
                       &selection, error) != 0);
    assert(!strcmp(error, "path_not_safe_regular_file"));

    assert(select_path(new_path, legacy_path, selected, 2,
                       &selection, error) != 0);
    assert(!strcmp(error, "selected_path_too_long"));
    assert(select_path("relative", legacy_path, selected, sizeof(selected),
                       &selection, error) != 0);
    assert(!strcmp(error, "path_not_safe_regular_file"));
    assert(jmx_path_select_immutable(new_path, legacy_path, NULL, 0,
                                     &selection, error, sizeof(error)) != 0);
    assert(!strcmp(error, "invalid_argument"));

    assert(mkdir(new_dir, 0700) == 0);
    assert(mkdir(legacy_dir, 0700) == 0);
    assert(jmx_path_select_immutable_file_set(new_dir, legacy_dir, ".list",
                                              &set, error, sizeof(error)) == 0);
    assert(set.count == 0);
    jmx_path_immutable_file_set_free(&set);
    assert(snprintf(file_path, sizeof(file_path), "%s/a.list", new_dir) <
           (int)sizeof(file_path));
    write_file(file_path, "/new-only\n");
    assert(snprintf(file_path, sizeof(file_path), "%s/b.list", legacy_dir) <
           (int)sizeof(file_path));
    write_file(file_path, "/legacy-only\n");
    assert(snprintf(file_path, sizeof(file_path), "%s/c.list", new_dir) <
           (int)sizeof(file_path));
    write_file(file_path, "/identical\n");
    assert(snprintf(file_path, sizeof(file_path), "%s/c.list", legacy_dir) <
           (int)sizeof(file_path));
    write_file(file_path, "/identical\n");
    assert(jmx_path_select_immutable_file_set(new_dir, legacy_dir, ".list",
                                              &set, error, sizeof(error)) == 0);
    assert(set.count == 3);
    assert(!strcmp(set.items[0].name, "a.list"));
    assert(set.items[0].selection == JMX_PATH_SELECTION_NEW);
    assert(set.items[0].selected_fd >= 0);
    assert(!strcmp(set.items[1].name, "b.list"));
    assert(set.items[1].selection == JMX_PATH_SELECTION_LEGACY);
    assert(!strcmp(set.items[2].name, "c.list"));
    assert(set.items[2].selection == JMX_PATH_SELECTION_IDENTICAL_NEW);
    jmx_path_immutable_file_set_free(&set);

    assert(snprintf(file_path, sizeof(file_path), "%s/c.list", legacy_dir) <
           (int)sizeof(file_path));
    write_file(file_path, "/different\n");
    assert(jmx_path_select_immutable_file_set(new_dir, legacy_dir, ".list",
                                              &set, error, sizeof(error)) != 0);
    assert(!strcmp(error, "path_identity_conflict"));
    assert(set.count == 0);
    assert(unlink(file_path) == 0);
    assert(snprintf(file_path, sizeof(file_path), "%s/d.list", legacy_dir) <
           (int)sizeof(file_path));
    assert(symlink(new_path, file_path) == 0);
    assert(jmx_path_select_immutable_file_set(new_dir, legacy_dir, ".list",
                                              &set, error, sizeof(error)) != 0);
    assert(!strcmp(error, "path_not_safe_regular_file"));
    assert(unlink(file_path) == 0);

    assert(snprintf(file_path, sizeof(file_path), "%s/a.list", new_dir) <
           (int)sizeof(file_path));
    assert(unlink(file_path) == 0);
    assert(snprintf(file_path, sizeof(file_path), "%s/b.list", legacy_dir) <
           (int)sizeof(file_path));
    assert(unlink(file_path) == 0);
    assert(snprintf(file_path, sizeof(file_path), "%s/c.list", new_dir) <
           (int)sizeof(file_path));
    assert(unlink(file_path) == 0);
    assert(rmdir(new_dir) == 0);
    assert(rmdir(legacy_dir) == 0);

    assert(unlink(new_path) == 0);
    assert(rmdir(directory_path) == 0);
    assert(rmdir(root) == 0);
    puts("ok: immutable path provider runtime fixture");
    return 0;
}
