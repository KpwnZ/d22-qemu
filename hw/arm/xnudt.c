#include "qemu/osdep.h"
#include "qemu-common.h"
#include "hw/arm/xnu.h"
#include "hw/arm/xnudt.h"

// the code here is based on
// bazad's devicetree parser and the work of zhuowei and alephsecurity

static
void arm_load_xnu_devicetree(struct arm_boot_info *info,
                             gchar *dt,
                             gchar *ramdisk) 
{
    // todo: implement
    XNUDTNode *root = arm_parse_xnu_devicetree(dt);
    
}

XNUDTNode *arm_parse_xnu_devicetree(gchar *blob) 
{
	XNUDTNode *root = arm_do_parse_xnu_devicetree(&blob);
#ifdef DEBUG_XNU_DEVICETREE
	printf("[+] loaded root node with %u properties and %d children\n", root->nprops, root->nchildren);
#endif  // DEBUG_XNU_DEVICETREE

    XNUDTNode *child = arm_search_xnu_devicetree_node_by_name(root, "arm-io");
    assert(child != NULL);
    
    XNUDTProp *prop = arm_get_xnu_devicetree_prop(child, "ranges");
    assert(prop != NULL);

    hwaddr *ranges = (hwaddr *)prop->value;
    hwaddr soc_base_pa = ranges[1];
    printf("[+] soc_base_pa: 0x%llx\n", soc_base_pa);

    child = arm_search_xnu_devicetree_node_by_name(child, "uart0");
    assert(child != NULL);

    prop = arm_get_xnu_devicetree_prop(child, "boot-console");
    assert(prop != NULL);
    
    prop = arm_get_xnu_devicetree_prop(child, "reg");
    assert(prop != NULL);

    hwaddr *uart_offset = (hwaddr *)prop->value;
    hwaddr uart_base_pa = soc_base_pa + uart_offset[0];
    printf("[+] uart_base_pa: 0x%llx\n", uart_base_pa);
    
	return root;
}

XNUDTNode *arm_do_parse_xnu_devicetree(gchar **blob) 
{
	XNUDTNode *node = g_new0(XNUDTNode, 1);
	node->nprops = *(uint32_t *)*blob;
	*blob += sizeof(uint32_t);
	node->nchildren = *(uint32_t *)*blob;
	*blob += sizeof(uint32_t);

	if (node->nprops == 0) {
		printf("[!] invalid node\n");
		abort();
	}
	for (int i = 0; i < node->nprops; ++i) {
		XNUDTProp *prop = arm_read_xnu_devicetree_prop(blob);
		node->properties = g_list_append(node->properties, prop);
#ifdef DEBUG_XNU_DEVICETREE
        if (strncmp(prop->value, "uart0", prop->length) == 0) {
            printf("[*] parsing prop %s\n", prop->name);
		}
#endif
	}
	for (int i = 0; i < node->nchildren; ++i) {
		XNUDTNode *child = arm_do_parse_xnu_devicetree(blob);
		node->children = g_list_append(node->children, child);
	}
	return node;
}

XNUDTProp *arm_read_xnu_devicetree_prop(gchar **blob) 
{
	XNUDTProp *prop = g_new0(XNUDTProp, 1);
	memcpy(prop->name, *blob, kPropNameLength);
	*blob += kPropNameLength;
	prop->length = *(uint32_t *)*blob & ~0x80000000;
	*blob += sizeof(uint32_t);
	if (prop->length > 0) {
		prop->value = g_malloc0(prop->length);
		memcpy(prop->value, *blob, prop->length);
		*blob += prop->length;
	}
	*blob = (gchar *)(((uint64_t)*blob + 0x3) & ~0x3);  // padding
	return prop;
}

XNUDTNode *arm_search_xnu_devicetree_node_by_name(XNUDTNode *node, const char *name) 
{
    assert(node != NULL);
    assert(name != NULL);
    XNUDTNode *child = NULL;
    XNUDTProp *prop = NULL;
    for(GList *l = node->children; l != NULL; l = l->next) {
        child = (XNUDTNode *)l->data;

        prop = arm_get_xnu_devicetree_prop(child, "name");

        if (strncmp(prop->value, name, prop->length) == 0) {
            return child;
        }
    }
    return NULL;
}

XNUDTProp *arm_get_xnu_devicetree_prop(XNUDTNode *node, const char *name) 
{
    for(GList *l = node->properties; l != NULL; l = l->next) {
        XNUDTProp *prop = (XNUDTProp *)l->data;
        if (strncmp((const char *)&prop->name[0], name, kPropNameLength) == 0) {
            return prop;
        }
    }
    return NULL;
}

// XNUDTProp *arm_set_xnu_devicetree_prop(XNUDTProp *n, const char *name, uint32_t size, uint8_t *val) {
//     XNUDTProp *prop;
//     assert(n && name && val);

//     prop = arm_search_xnu_devicetree_node_by_name(n, name);

//     if (!prop) {
//         prop = g_new0(XNUDTProp, 1);
//         n->props = g_list_append(n->props, prop);
//         n->prop_count++;
//     } else {
//         g_free(prop->value);
//         prop->value = NULL;
//         memset(prop, 0, sizeof(XNUDTProp));
//     }
//     strncpy((char *)prop->name, name, kPropNameLength);
//     prop->length = size;
//     prop->value = g_malloc0(size);
//     memcpy(prop->value, val, size);

//     return prop;
// }