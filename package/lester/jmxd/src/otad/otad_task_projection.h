 /* SPDX-License-Identifier: GPL-2.0-or-later */
 /*
  * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
  *
  * OTA task status in product-plane.v1 task contract format.
  * Read-only projection of otad's internal state machine.
  */
 #ifndef DREAMINGWRT_OTAD_TASK_PROJECTION_H
 #define DREAMINGWRT_OTAD_TASK_PROJECTION_H
 
 #include <json-c/json.h>
 
 /*
  * Build a product-plane.v1 ota.task response from the current
  * otad state. Returns idle when no operation is active.
  * Caller owns the result.
  */
 struct json_object *otad_task_projection_get(void);
 
 /*
  * Register the task_projection ubus method on the otad object.
  * Called during otad_ubus_start() setup -- adds "task_projection"
  * to the existing dreamingwrt.otad methods.
  *
  * Since the otad ubus object is statically defined, the simpler
  * approach is to expose otad_task_projection_get() and let the
  * existing status handler or a new handler call it.
  */
 
 #endif
