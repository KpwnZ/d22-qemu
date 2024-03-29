#ifndef D22_IDEVICE_H
#define D22_IDEVICE_H

#include "qemu-common.h"
#include "exec/hwaddr.h"
#include "hw/boards.h"
#include "hw/arm/boot.h"
#include "hw/arm/xnu.h"
#include "hw/arm/xnudt.h"
#include "exec/memory.h"
#include "cpu.h"
#include "sysemu/kvm.h"
#include "hw/arm/apple-aic.h"

#define DEBUG_D22_IDEVICE

#define TYPE_D22          "d22-idevice"
#define TYPE_D22_MACHINE  MACHINE_TYPE_NAME(TYPE_D22)
#define D22_IDEVICE_MACHINE(obj) \
    OBJECT_CHECK(D22IDeviceMachineState, (obj), TYPE_D22_MACHINE)

// D22 iDevice 
typedef struct D22IDeviceMachineState {
    MachineState parent;
    char kernelcache_fn[1024];
    char devicetree_fn[1024];
    char ramdisk_fn[1024];
    char trustcache_fn[1024];
    char nvram_fn[1024];
    char bootargs[1024];
    XNUDTNode *devicetree;
    hwaddr bootargs_pa;
    hwaddr uart_serial_pa;
    hwaddr pc_pa;
    ARMCPU *cpu;
    int enable_ramfb;
    struct arm_boot_info bootinfo;
    struct xnu_boot_args boot_args;

    hwaddr soc_base_pa;
    hwaddr soc_size;
    struct {
        AppleAICState *aic;
    } peripherals;
    
} D22IDeviceMachineState;

#endif
