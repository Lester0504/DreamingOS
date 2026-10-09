/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef WEBD_API_FINGERPRINT_INTERNAL_H
#define WEBD_API_FINGERPRINT_INTERNAL_H

#include <stddef.h>

struct http_req;
struct json_object;

/* Entry points defined in api_fingerprint.c, used from the main TU:
 * handle_client() dispatch, and the model-image resolver is passed as a
 * callback by the wifi aggregate response. */
int webd_fingerprint_model_image_resolve(
    const char *model, char *image_url, size_t image_url_len,
    char *matched_model, size_t matched_model_len);
struct json_object *webd_fingerprint_index_response(const struct http_req *req);
void webd_client_upload_store_init(void);
struct json_object *webd_fingerprint_upload_response(struct json_object *body);

#endif /* WEBD_API_FINGERPRINT_INTERNAL_H */
