#ifndef JMX_HUGINN_H
#define JMX_HUGINN_H

/* Huginn-Muninn external fingerprint DB integration.
 * Opens /etc/dreamingwrt/huginn_muninn.db read-only.
 * Silent if file missing. */

typedef struct {
    char device_name[128];
    char device_type[64];
    char device_vendor[64];
} huginn_result_t;

/* Initialize: open the external DB if present. Safe to call multiple times. */
void huginn_init(void);

/* Close the external DB. */
void huginn_close(void);

/* Lookup by DHCP option 55 string (e.g. "1,3,6,15,28,51,58,59").
 * Returns 0 on match, -1 on miss or error. Silent on all failures. */
int huginn_lookup_by_option55(const char *option55, huginn_result_t *out);

/* Lookup by DHCP vendor class (option 60).
 * Returns 0 on match, -1 on miss or error. */
int huginn_lookup_by_vendor_class(const char *vendor_class, huginn_result_t *out);

#endif
