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
#include "hw/arm/boot.h"
#include "hw/arm/xnu.h"
#include "hw/arm/xnudt.h"
#include "ui/console.h"
#include "framebuffer.h"
#include <stdint.h>
#include "hw/display/d22-display.h"

#define DEBUG_D22_DISPLAY
#ifdef DEBUG_D22_DISPLAY
#define D22_DISPLAY_DEBUG_PRINT(fmt, ...) \
    do { \
        fprintf(stdout, "\033[33m[D22_DISPLAY] " fmt "\033[0m", ## __VA_ARGS__); \
        fprintf(stdout, "\033[0m"); \
        fflush(stdout); \
    } while (0)
#else
#define D22_DISPLAY_DEBUG_PRINT(fmt, ...)
#endif

static void d22_display_update(void *opaque) {
    D22_DISPLAY_DEBUG_PRINT("display update\n");
}

static const GraphicHwOps vcon_ops = {
    .gfx_update = d22_display_update,
};

static void d22_display_realize(DeviceState *dev, Error **errp) {
    D22Display *s = D22_DISPLAY(dev);
    s->vcon = graphic_console_init(dev, 0, &vcon_ops, 0);
}

static void d22_display_class_init(ObjectClass *klass, void *data) {
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->desc = "D22 Display";
    dc->realize = d22_display_realize;
}

static const TypeInfo d22_display_info = {
    .name = TYPE_D22_DISPLAY,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(D22Display),
    .class_init = d22_display_class_init,
};

static void d22_display_register_types(void)
{
    type_register_static(&d22_display_info);
}

type_init(d22_display_register_types);
