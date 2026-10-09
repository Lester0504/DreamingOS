// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_DATASET_PATH_H
#define DREAMINGWRT_DATASET_PATH_H

/*
 * One resolver for every process that opens a relocatable dataset -- the
 * writer, its readers in other daemons, and co-writers. The authority is
 * /etc/dreamingwrt/storage/assignments.json (storage_binding.c): a non-empty
 * active_path wins, otherwise the compiled default for the use.
 *
 * Returned strings are immutable and stay valid for the life of the process:
 * when a binding changes, a fresh string is allocated and the old one is left
 * in place, so a reader thread never sees a half-rewritten path. The number of
 * distinct values a process can observe is bounded by binding changes, which
 * are operator actions, so the retained strings are a few bytes each.
 *
 * `use` and `leaf` must be string literals (they are cached by pointer).
 */

/* "audit" -> directory; "aegis", "log" -> database file. */
const char *jmx_dataset_path(const char *use);
/* jmx_dataset_path(use) + "/" + leaf, for directory uses ("audit", "audit.db"). */
const char *jmx_dataset_child(const char *use, const char *leaf);

#endif
