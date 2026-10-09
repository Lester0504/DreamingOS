// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef NAS_ARCHIVE_CONTRACT_H
#define NAS_ARCHIVE_CONTRACT_H
#define NAS_ARCHIVE_FORMAT "{\"list\":true,\"create\":true,\"extract\":true,\"add\":true,\"delete\":true,\"preview\":true}"
#define NAS_ARCHIVE_CAPABILITIES \
    "{\"formats\":{\"zip\":" NAS_ARCHIVE_FORMAT ",\"tar\":" NAS_ARCHIVE_FORMAT \
    ",\"tar.gz\":" NAS_ARCHIVE_FORMAT ",\"tar.xz\":" NAS_ARCHIVE_FORMAT \
    ",\"tar.bz2\":" NAS_ARCHIVE_FORMAT "},\"conflicts\":[\"error\",\"skip\",\"replace\"]," \
    "\"password\":false,\"add\":true,\"delete\":true,\"preview\":true,\"preview_max_bytes\":262144,\"preview_type\":\"utf8_text\"}"
#endif
