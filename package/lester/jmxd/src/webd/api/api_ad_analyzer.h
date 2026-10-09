// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef API_AD_ANALYZER_H
#define API_AD_ANALYZER_H
#include "api_router.h"
extern const struct jmx_api_route ad_analyzer_api_routes[];
void ad_analyzer_start(void);
void ad_analyzer_stop(void);
#endif
