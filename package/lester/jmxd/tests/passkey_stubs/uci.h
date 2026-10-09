#ifndef DREAMINGWRT_TEST_UCI_H
#define DREAMINGWRT_TEST_UCI_H

struct uci_context;

struct uci_element {
    struct uci_element *next;
};

struct uci_list {
    struct uci_element *next;
};

struct uci_section {
    struct uci_element e;
    const char *type;
};

struct uci_package {
    struct uci_list sections;
};

#define UCI_OK 0
#define uci_foreach_element(list, element) \
    for ((element) = (list)->next; (element); (element) = (element)->next)
#define uci_to_section(element) ((struct uci_section *)(element))

struct uci_context *uci_alloc_context(void);
void uci_free_context(struct uci_context *ctx);
int uci_load(struct uci_context *ctx, const char *name,
             struct uci_package **package);
const char *uci_lookup_option_string(struct uci_context *ctx,
                                     struct uci_section *section,
                                     const char *name);

#endif
