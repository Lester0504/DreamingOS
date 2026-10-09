// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_FLOWD_RUNTIME_SAMPLER_H
#define DREAMINGWRT_FLOWD_RUNTIME_SAMPLER_H

int flowd_runtime_sampler_command(int argc, char **argv);
int flowd_runtime_sampler_init(const char *argv0);
int flowd_runtime_sampler_start(void);
void flowd_runtime_sampler_stop(void);

#endif
