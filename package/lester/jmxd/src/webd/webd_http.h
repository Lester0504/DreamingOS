// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __DREAMINGWRT_WEBD_HTTP_H__
#define __DREAMINGWRT_WEBD_HTTP_H__

#include <stddef.h>
#include <json-c/json.h>

int http_send(int fd, int status, const char *status_text,
              const char *content_type, const char *body, int body_len);
int http_send_raw(int fd, int status, const char *content_type,
                  const void *body, size_t body_len,
                  const char *cache_control);
int http_send_download(int fd, int status, const char *content_type,
                       const char *filename, const void *body, size_t body_len);
int http_send_file_path(int fd, const char *path, const char *method);
int http_send_file_path_encoded(int fd, const char *path, const char *method, int accepts_gzip);
int http_send_json(int fd, int status, struct json_object *resp);
int http_send_json_cookie(int fd, int status, struct json_object *resp,
                          const char *cookie);
int http_send_sse_header(int fd);

#endif
