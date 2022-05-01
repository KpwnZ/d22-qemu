#ifndef XNUMEM_H
#define XNUMEM_H

#include "qemu-common.h"
#include "qemu/osdep.h"

#define align64(addr) 	 (((addr) + 0xffffull) & ~0xffffull)
#define align64low(addr) ((addr) & ~0xffffull)

void set_g_phys_base(hwaddr phys_base);
void set_g_virt_base(hwaddr virt_base);
hwaddr vtop_bases(hwaddr va, hwaddr phys_base, hwaddr virt_base);
hwaddr ptov_bases(hwaddr pa, hwaddr phys_base, hwaddr virt_base);
hwaddr vtop_static(hwaddr va);
hwaddr ptov_static(hwaddr pa);
void allocate_ram(MemoryRegion *top, const char *name, hwaddr addr,
                  hwaddr size);
void allocate_and_copy(MemoryRegion *mem, AddressSpace *as,
                       const char *name, hwaddr pa, hwaddr size,
                       void *buf);

#endif
