#ifndef XNUDT_H
#define XNUDT_H

#include "hw/arm/xnu.h"

#define ALIGN(a) (((uint64_t)a + 0x3) & ~0x3)

#define PRINT_STYLE_INT 0
#define PRINT_STYLE_HEX 1
#define PRINT_STYLE_STR 2

// XNUDTNode *arm_load_xnu_devicetree(gchar *blob);
XNUDTProp *arm_read_xnu_devicetree_prop(gchar **blob);
XNUDTNode *arm_do_parse_xnu_devicetree(gchar **blob);
XNUDTProp *arm_search_xnu_devicetree_prop_by_name(XNUDTNode *node, const char *name);
XNUDTProp *arm_get_xnu_devicetree_prop(XNUDTNode *node, const char *name);
XNUDTProp *arm_set_xnu_devicetree_prop(XNUDTProp *n, const char *name, uint32_t size, uint8_t *val);
void arm_print_xnu_devicetree_node(XNUDTNode *node, int depth);
void arm_add_xnu_devicetree_prop(XNUDTNode *root, const char *name, uint32_t len, const char *value, const char *path);
void arm_remove_xnu_devicetree_prop(XNUDTNode *root, const char *name, const char *path);
void arm_save_devicetree(XNUDTNode *root, const char *path);
void arm_write_devicetree_to_memory(XNUDTNode *root, uint8_t **buf, uint64_t *size);
XNUDTNode *arm_parse_xnu_devicetree(gchar *blob);
XNUDTProp *arm_get_xnu_devicetree_prop(XNUDTNode *node, const char *name);
XNUDTNode *arm_get_xnu_devicetree_node_by_name(XNUDTNode *node, const char *name);
XNUDTNode *arm_get_xnu_devicetree_node_by_path(XNUDTNode *node, const char *path);
void style_print_data(uint8_t *prop_name, uint8_t *data, uint32_t len);
#endif
