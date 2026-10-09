// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TVHOME_WS_H
#define TVHOME_WS_H
struct http_req;
int tvhome_ws_count(const char *terminal_id);
void tvhome_ws_session(int fd, const struct http_req *req);
#endif
