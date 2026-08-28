/* Compatibility shim: the single source of the route wire contract is
 * routed/jmx_route.h.  Core files that historically included the root copy
 * keep using this include path.  No guard here on purpose: routed/jmx_route.h
 * owns the __JMX_ROUTE_H__ guard. */
#include "routed/jmx_route.h"
