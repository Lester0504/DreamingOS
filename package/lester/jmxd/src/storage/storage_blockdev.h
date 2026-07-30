// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_STORAGE_BLOCKDEV_H
#define DREAMINGWRT_STORAGE_BLOCKDEV_H

#include <json-c/json.h>

/*
 * Read-only block-device inventory for the Web storage manager.
 *
 * jmx_storage_partitions_get() returns a { "storage": { disks[], capabilities } }
 * envelope compatible with storage-partitions.js. Destructive partition write
 * capabilities are advertised honestly (false) until a protected partition
 * transaction contract exists; the endpoint still supplies the real partition
 * table, per-partition mount/system flags and sector geometry that the mounts
 * fallback cannot fully provide.
 *
 * jmx_storage_raid_get() returns a { "raid": { arrays[], disks[], recoverable[],
 * capabilities } } envelope compatible with storage-raid.js. Arrays/recoverable
 * are parsed from /proc/mdstat + mdadm (real, never fabricated); create/recover/
 * delete capabilities are gated false pending a destructive-op safety contract.
 *
 * jmx_storage_raid_scan() performs a non-destructive `mdadm --examine --scan`
 * and returns any assemble candidates found on attached disks.
 */
struct json_object *jmx_storage_partitions_get(void);
struct json_object *jmx_storage_raid_get(void);
struct json_object *jmx_storage_raid_scan(void);

#endif /* DREAMINGWRT_STORAGE_BLOCKDEV_H */
