// Run on the target with a firmware stream on stdin. Never invokes apply.
#include "../webd/webd_upload_staging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    struct webd_upload_meta meta;
    char error[128] = "";
    unsigned char buffer[65536];
    const char *owner = "web:ota-tmp-probe";
    uint64_t offset = 0;
    int rc = 1;
    if (argc != 3) return 2;
    if (webd_upload_staging_check_capacity(UINT64_MAX, error, sizeof(error)) == 0 ||
        strcmp(error, "staging_insufficient_space")) return 3;
    if (webd_upload_begin(owner, "ota-remote", "firmware", "ota-probe.bin",
                          strtoull(argv[1], NULL, 10), 0, 300, &meta,
                          error, sizeof(error)) != 0) {
        fprintf(stderr, "begin: %s\n", error);
        return 4;
    }
    for (;;) {
        size_t n = fread(buffer, 1, sizeof(buffer), stdin);
        if (!n) break;
        if (webd_upload_append(owner, meta.upload_id, offset, buffer, n,
                               NULL, error, sizeof(error)) != 0)
            goto done;
        offset += n;
    }
    if (ferror(stdin)) goto done;
    if (webd_upload_finalize(owner, meta.upload_id, argv[2], &meta,
                             error, sizeof(error)) != 0) goto done;
    printf("PASS root=%s bytes=%llu sha256=%s; no apply\n",
           WEBD_UPLOAD_DEFAULT_ROOT, (unsigned long long)meta.size_bytes, meta.sha256);
    rc = 0;
done:
    if (rc) fprintf(stderr, "download: %s\n", error);
    if (webd_upload_delete(owner, meta.upload_id, error, sizeof(error)) != 0) {
        fprintf(stderr, "cleanup: %s\n", error);
        return 5;
    }
    return rc;
}
