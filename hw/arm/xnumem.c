#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/error-report.h"
#include "sysemu/numa.h"
#include "exec/memory.h"
#include "hw/boards.h"
#include "hw/arm/xnu.h"
#include "hw/arm/xnumem.h"

hwaddr g_virt_base = 0;
hwaddr g_phys_base = 0;

void set_g_phys_base(hwaddr phys_base)
{
    g_phys_base = phys_base;
}

void set_g_virt_base(hwaddr virt_base)
{
    g_virt_base = virt_base;
}

hwaddr vtop_bases(hwaddr va, hwaddr phys_base, hwaddr virt_base)
{
    if ((0 == virt_base) || (0 == phys_base)) {
        abort();
    }
    return va - virt_base + phys_base;
}

hwaddr ptov_bases(hwaddr pa, hwaddr phys_base, hwaddr virt_base)
{
    if ((0 == virt_base) || (0 == phys_base)) {
        abort();
    }
    return pa - phys_base + virt_base;
}

hwaddr vtop_static(hwaddr va)
{
    return vtop_bases(va, g_phys_base, g_virt_base);
}

hwaddr ptov_static(hwaddr pa)
{
    return ptov_bases(pa, g_phys_base, g_virt_base);
}

void allocate_ram(MemoryRegion *top, const char *name, hwaddr addr,
                  hwaddr size)
{
    MemoryRegion *sec = g_new(MemoryRegion, 1);
    memory_region_init_ram(sec, NULL, name, size, NULL);
    memory_region_add_subregion(top, addr, sec);
}


void allocate_and_copy(MemoryRegion *mem, AddressSpace *as,
                       const char *name, hwaddr pa, hwaddr size,
                       void *buf)
{
    if (mem) {
        allocate_ram(mem, name, pa, align64(size));
    }
    address_space_rw(as, pa, MEMTXATTRS_UNSPECIFIED, (uint8_t *)buf, size, 1);
}
