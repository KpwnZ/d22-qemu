// Copyright (C) 2024 Xiao
// 
// This file is part of d22-qemu.
// 
// d22-qemu is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// d22-qemu is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with d22-qemu.  If not, see <http://www.gnu.org/licenses/>.

#ifndef APPLE_AIC_H
#define APPLE_AIC_H

#include "cpu.h"
#include "exec/hwaddr.h"
#include "exec/memory.h"
#include "hw/arm/boot.h"
#include "hw/arm/xnu.h"
#include "hw/arm/xnudt.h"
#include "hw/boards.h"
#include "qemu-common.h"
#include "qom/object.h"
#include "hw/sysbus.h"

// #define DEBUG_APPLE_AIC

#define TYPE_APPLE_AIC "apple.aic"
OBJECT_DECLARE_SIMPLE_TYPE(AppleAICState, APPLE_AIC)

typedef struct AppleAICChip {
    AppleAICState *aic_state;
    MemoryRegion *iomem;
} AppleAICChip;

typedef struct AppleAICState {
    SysBusDevice parent;
    hwaddr mapping_base;
    hwaddr mapping_size;
    unsigned cpus_cnt;
    unsigned ipid_cnt;
    unsigned irq_cnt;
    qemu_irq *irqs;
    QEMUTimer *timer;
    struct {
        void *aic_state;
        MemoryRegion *iomem;
    } chip;
    ARMCPU *cpu;
} AppleAICState;

AppleAICState *create_apple_aic(hwaddr soc_base, unsigned cpus_cnt, XNUDTNode *node);

#endif
