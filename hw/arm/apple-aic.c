/**
 * Copyright (C) 2024 Xiao
 * 
 * This file is part of d22-qemu.
 * 
 * d22-qemu is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * d22-qemu is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with d22-qemu.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "qemu/module.h"
#include "hw/arm/boot.h"
#include "hw/arm/xnu.h"
#include "hw/arm/xnudt.h"
#include "hw/arm/apple-aic.h"

#define DEBUG_APPLE_AIC 1

#if DEBUG_APPLE_AIC
#define APPLE_AIC_DEBUG_PRINT(fmt, ...) \
    do { \
        fprintf(stdout, "\033[33m[AppleAIC] " fmt "\033[0m", ## __VA_ARGS__); \
        fprintf(stdout, "\033[0m"); \
        fflush(stdout); \
    } while (0)
#else
#define APPLE_AIC_DEBUG_PRINT(fmt, ...)
#endif

static uint64_t apple_aic_read(void *opaque, hwaddr offset, unsigned size) {
    AppleAICState *aic = APPLE_AIC(opaque);
    APPLE_AIC_DEBUG_PRINT("read at offset 0x%llx size %u\n", offset, size);
    uint64_t ret = 0;
    if (offset < 0x1000) {
        switch (offset)
        {
        case 0x0:
            ret = 2;
            break;
        case 0x4:
            ret = aic->irq_cnt;
            break;
        default:
            break;
        }
    }
    return ret;
}

static void apple_aic_write(void *opaque, hwaddr offset, uint64_t value, unsigned size) {
    AppleAICState *aic = APPLE_AIC(opaque);
    APPLE_AIC_DEBUG_PRINT("write at offset 0x%llx value 0x%llx size %u\n", offset, value, size);
}

static const MemoryRegionOps apple_aic_ops = {
    .read = apple_aic_read,
    .write = apple_aic_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static void apple_aic_set_irq(void *opaque, int irq, int level) {
    AppleAICState *aic = APPLE_AIC(opaque);
    APPLE_AIC_DEBUG_PRINT("set irq %d level %d\n", irq, level);
}

static void init_apple_aic(Object *opaque) {
    AppleAICState *aic = APPLE_AIC(opaque);
    SysBusDevice *s = SYS_BUS_DEVICE(opaque);
    MemoryRegion *iomem = g_new(MemoryRegion, 1);
    memory_region_init_io(
        iomem, OBJECT(aic), &apple_aic_ops, opaque,
        TYPE_APPLE_AIC, aic->mapping_size
    );
    aic->chip.iomem = iomem;
    // connect aic->irq_cnt input gpio lines to the aic
    aic->irqs = g_new(qemu_irq, aic->cpus_cnt);
    qdev_init_gpio_in(DEVICE(opaque), apple_aic_set_irq, aic->irq_cnt);
    // output gpio lines to the cpus
    qdev_init_gpio_out(DEVICE(opaque), aic->irqs, aic->cpus_cnt);
    for (int i = 0; i < aic->cpus_cnt; i++) {
        sysbus_init_irq(s, &aic->irqs[i]);
    }
}

AppleAICState *create_apple_aic(hwaddr soc_base, unsigned cpus_cnt, XNUDTNode *node)
{
    DeviceState *dev;
    SysBusDevice *s;
    AppleAICState *aic;

    dev = qdev_new(TYPE_APPLE_AIC);
    aic = APPLE_AIC(dev);

    /* 
     * we need to update the /device-tree/aic/#main-cpus property 
     * according to the number of cpus_cnt
     * the mapping base should be soc_base + prop->reg[0]
     * the mapping size should be prop->reg[1]
     */

    XNUDTProp *prop = arm_get_xnu_devicetree_prop(node, "#main-cpus");
    assert(prop);
    (*(uint32_t *)prop->value) = cpus_cnt;

    prop = arm_get_xnu_devicetree_prop(node, "reg");
    assert(prop);
    hwaddr mapping_base = soc_base + (*(uint64_t *)prop->value);
    hwaddr mapping_size = (*(uint64_t *)(prop->value + 8));
    APPLE_AIC_DEBUG_PRINT("mapping base: 0x%lx, size: 0x%lx\n", mapping_base, mapping_size);

    prop = arm_get_xnu_devicetree_prop(node, "ipid-mask");
    assert(prop);
    aic->ipid_cnt = prop->length / 4;

    aic->mapping_base = mapping_base;
    aic->mapping_size = mapping_size;
    aic->cpus_cnt = cpus_cnt;
    aic->irq_cnt = aic->ipid_cnt * 32;
    // account for the aic chip object
    // lazy, 1 cpu for now
    init_apple_aic(dev);
    
    return aic;
}

static void apple_aic_realize(DeviceState *dev, Error **errp) {
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    AppleAICState *aic = APPLE_AIC(dev);
}

static void reset_apple_aic(DeviceState *dev) {
    AppleAICState *aic = APPLE_AIC(dev);
    APPLE_AIC_DEBUG_PRINT("[AppleAIC] reset\n");
}

static void apple_aic_class_init(ObjectClass *c, void *data) {
    DeviceClass *dc = DEVICE_CLASS(c);
    dc->desc = "Apple Interrupt Controller";
    dc->realize = apple_aic_realize;
    dc->reset = reset_apple_aic;
}

static const TypeInfo apple_aic_info = {
    .name = TYPE_APPLE_AIC,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleAICState),
    .class_init = apple_aic_class_init,
};

static void apple_aic_register_types(void) {
    type_register_static(&apple_aic_info);
}

type_init(apple_aic_register_types);
