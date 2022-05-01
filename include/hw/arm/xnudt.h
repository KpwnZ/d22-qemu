#ifndef XNUDT_H
#define XNUDT_H

#include "hw/arm/xnu.h"

XNUDTProp *arm_get_xnu_devicetree_prop(XNUDTNode *node, const char *name); 
XNUDTNode *arm_search_xnu_devicetree_node_by_name(XNUDTNode *node, const char *name);

#endif
