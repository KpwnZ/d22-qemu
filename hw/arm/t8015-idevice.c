#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "hw/arm/boot.h"
#include "exec/address-spaces.h"
#include "hw/boards.h"
#include "hw/arm/d22-idevice.h"
#include "sysemu/sysemu.h"
#include "sysemu/reset.h"
#include "exec/memory.h"
#include "hw/platform-bus.h"
#include "hw/arm/exynos4210.h"
#include "hw/arm/apple-aic.h"
#include "hw/arm/xnudt.h"
#include "hw/display/d22-display.h"

static void d22_create_s3c_uart(D22IDeviceMachineState* m, Chardev *chr, XNUDTNode *node)
{
    assert(node != NULL);
    qemu_irq irq;
    SysBusDevice *s;
    hwaddr base = 0; // 0x22e600000;
    XNUDTProp *prop = arm_get_xnu_devicetree_prop(node, "reg");
    assert(prop != NULL);
    base = *(uint64_t *)(prop->value);
    base += m->soc_base_pa;
    prop = arm_get_xnu_devicetree_prop(node, "interrupts");
    int int_v = *(uint32_t *)(prop->value);
    DeviceState *dev = exynos4210_uart_create(base, 256, 0, chr, qdev_get_gpio_in(DEVICE(m->peripherals.aic), int_v));
    if (!dev) {
        abort();
    }
}

static void d22_create_aic(void *opaque, XNUDTNode *node) {
    assert(node != NULL);
    D22IDeviceMachineState *s = D22_IDEVICE_MACHINE((MachineState *)opaque);
    AppleAICState *aic = create_apple_aic(s->soc_base_pa, 1, node);
    aic->cpu = s->cpu;
    memory_region_add_subregion_overlap(
        get_system_memory(), aic->mapping_base, aic->chip.iomem, 0);
    qdev_connect_gpio_out(DEVICE(aic), 0, qdev_get_gpio_in(DEVICE(s->cpu), ARM_CPU_FIQ));
    s->peripherals.aic = aic;
}

static void d22_create_display(D22IDeviceMachineState *s) {
    s->boot_args.Video.v_display = 1;
    MemoryRegion *vram = g_new(MemoryRegion, 1);   
}

static void d22_cpu_reset(void *opaque) 
{
    D22IDeviceMachineState *nms = D22_IDEVICE_MACHINE((MachineState *)opaque);
    ARMCPU *cpu = nms->cpu;
    CPUState *cs = CPU(cpu);
    CPUARMState *env = &cpu->env; 
    cpu_reset(cs);
    env->xregs[0] = nms->bootargs_pa;
    env->pc = nms->pc_pa;
}

static void d22_machine_init(MachineState *machine)
{
    D22IDeviceMachineState *s = D22_IDEVICE_MACHINE(machine);
    MemoryRegion *sysmem;
    AddressSpace *as;
    ARMCPU *cpu;
    CPUState *cs;
    DeviceState *cpudev;

    // setting up cpu
    Object *cpuobj = object_new(machine->cpu_type);
    cpu = ARM_CPU(cpuobj);
    cs = CPU(cpu);
    cpudev = DEVICE(cpu);

    sysmem = get_system_memory();

    object_property_set_link(cpuobj, "memory", OBJECT(sysmem),
                             &error_abort);

    //set secure monitor to false
    object_property_set_bool(cpuobj, "has_el3", false, NULL);
    object_property_set_bool(cpuobj, "has_el2", false, NULL);
    object_property_set_bool(cpuobj, "realized", true, &error_fatal);

    as = cpu_get_address_space(cs, ARMASIdx_NS);
    object_unref(cpuobj);

    s->cpu = cpu;

    // setting up bootinfo
    uint64_t entry;
    s->bootinfo.kernel_filename = s->kernelcache_fn;
    s->bootinfo.dtb_filename = s->devicetree_fn;
    s->bootinfo.initrd_filename = s->ramdisk_fn;
    s->bootinfo.kernel_cmdline = s->bootargs;
    s->bootinfo.loader_start = 0x40000000;

    gchar *nvram_proxy_data = NULL;
    gsize nvram_proxy_len = 0;
    g_file_get_contents(s->nvram_fn, &nvram_proxy_data, &nvram_proxy_len, NULL);
    assert(nvram_proxy_data != NULL);

    gsize dt_len = 0;
    gchar *dt_data = NULL;
    g_file_get_contents(s->bootinfo.dtb_filename, &dt_data, &dt_len, NULL);
    assert(dt_data != NULL);
    XNUDTNode *devicetree = arm_load_xnu_devicetree(dt_data);
    s->devicetree = devicetree;

    // process devicetree
    XNUDTNode *node = arm_get_xnu_devicetree_node_by_path(devicetree, "/device-tree/arm-io");
    assert(node != NULL);
    XNUDTProp *prop = arm_get_xnu_devicetree_prop(node, "ranges");
    assert(prop != NULL);
    hwaddr *ranges = (uint64_t *)prop->value;
    s->soc_base_pa = ranges[1];
    s->soc_size = ranges[2];

    node = arm_get_xnu_devicetree_node_by_path(devicetree, "/device-tree/chosen");
    if (node) {
        arm_add_xnu_devicetree_prop(devicetree, "dram-base", 8, (const char *)&s->bootinfo.loader_start, "/device-tree/chosen");
        arm_add_xnu_devicetree_prop(devicetree, "dram-size", 8, (const char *)&s->bootinfo.ram_size, "/device-tree/chosen");
    }
    s->boot_args.memSize = s->bootinfo.ram_size;

    uint32_t aperture_count = 0, aperture_size = 0;
    arm_add_xnu_devicetree_prop(devicetree, "aperture-count", 4, (const char *)&aperture_count, "/device-tree/chosen/lock-regs/amcc");
    arm_add_xnu_devicetree_prop(devicetree, "aperture-size", 4, (const char *)&aperture_size, "/device-tree/chosen/lock-regs/amcc");

    uint32_t plane_count = 0;
    hwaddr amcc_addr = 0;
    uint32_t data32 = 0;
    arm_add_xnu_devicetree_prop(devicetree, "plane-count", 4, (const char *)&plane_count, "/device-tree/chosen/lock-regs/amcc");
    arm_add_xnu_devicetree_prop(devicetree, "aperture-phys-addr", 0, (const char *)&amcc_addr, "/device-tree/chosen/lock-regs/amcc");
    arm_add_xnu_devicetree_prop(devicetree, "cache-status-reg-offset", 4, (const char *)&data32, "/device-tree/chosen/lock-regs/amcc");
    arm_add_xnu_devicetree_prop(devicetree, "cache-status-reg-mask", 4, (const char *)&data32, "/device-tree/chosen/lock-regs/amcc");
    arm_add_xnu_devicetree_prop(devicetree, "cache-status-reg-value", 4, (const char *)&data32, "/device-tree/chosen/lock-regs/amcc");
    arm_add_xnu_devicetree_prop(devicetree, "page-size-shift", 4, (const char *)&data32, "/device-tree/chosen/lock-regs/amcc/amcc-ctrr-a");
    arm_add_xnu_devicetree_prop(devicetree, "lower-limit-reg-offset", 4, (const char *)&data32, "/device-tree/chosen/lock-regs/amcc/amcc-ctrr-a");
    arm_add_xnu_devicetree_prop(devicetree, "lower-limit-reg-mask", 4, (const char *)&data32, "/device-tree/chosen/lock-regs/amcc/amcc-ctrr-a");
    arm_add_xnu_devicetree_prop(devicetree, "upper-limit-reg-offset", 4, (const char *)&data32, "/device-tree/chosen/lock-regs/amcc/amcc-ctrr-a");
    arm_add_xnu_devicetree_prop(devicetree, "upper-limit-reg-mask", 4, (const char *)&data32, "/device-tree/chosen/lock-regs/amcc/amcc-ctrr-a");
    arm_add_xnu_devicetree_prop(devicetree, "lock-reg-offset", 4, (const char *)&data32, "/device-tree/chosen/lock-regs/amcc/amcc-ctrr-a");
    arm_add_xnu_devicetree_prop(devicetree, "lock-reg-mask", 4, (const char *)&data32, "/device-tree/chosen/lock-regs/amcc/amcc-ctrr-a");
    arm_add_xnu_devicetree_prop(devicetree, "lock-reg-value", 4, (const char *)&data32, "/device-tree/chosen/lock-regs/amcc/amcc-ctrr-a");
    
    MemoryRegion *sysram = g_new(MemoryRegion, 1);

    memory_region_init_ram(sysram, NULL, "sys.ram", s->bootinfo.ram_size, NULL);
    memory_region_add_subregion(sysmem, s->bootinfo.loader_start, sysram);

    MemoryRegion *amcc = g_new(MemoryRegion, 1);
    MemoryRegion *aic = g_new(MemoryRegion, 1);

    memory_region_init_ram(amcc, NULL, "amcc.ram", 0x00300000, NULL);
    memory_region_add_subregion(sysmem, 0x200000000, amcc);

    qemu_devices_reset();

    xnu_init_memory(&s->bootinfo, s, devicetree, (const uint8_t *)nvram_proxy_data, &entry, as, sysmem, &s->pc_pa, &s->bootargs_pa);
    d22_create_aic(s, arm_get_xnu_devicetree_node_by_path(devicetree, "/device-tree/arm-io/aic"));
    d22_create_s3c_uart(s, serial_hd(0), arm_get_xnu_devicetree_node_by_path(devicetree, "/device-tree/arm-io/uart0"));

    qdev_connect_gpio_out(cpudev, GTIMER_VIRT, qdev_get_gpio_in(cpudev, ARM_CPU_FIQ));

    qemu_register_reset(d22_cpu_reset, s);
}

static void d22_load_kernelpatch(AddressSpace *as)
{
    
}

static void d22_machine_class_init(ObjectClass *class, void *data) 
{
    MachineClass *mc = MACHINE_CLASS(class);
    mc->desc = "D22/D221 iDevice(iPhone X)";
    mc->init = d22_machine_init;

    // set cpu type to cortex-a57
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-a57");
    mc->default_ram_id = "t8015.ram";
    mc->no_cdrom = 1;
    mc->no_floppy = 1;
    mc->no_parallel = 1;
    mc->minimum_page_bits = 12;
}

static char *d22_machine_get_boot_kernel(Object *obj, Error **errp) 
{
    D22IDeviceMachineState *s = D22_IDEVICE_MACHINE(obj);
    return g_strdup(s->kernelcache_fn);
}

static void d22_machine_set_boot_kernel(Object *obj, const char *value, Error **errp) 
{
    D22IDeviceMachineState *s = D22_IDEVICE_MACHINE(obj);
    g_strlcpy(s->kernelcache_fn, value, sizeof(s->kernelcache_fn));
}

static char *d22_machine_get_boot_devicetree(Object *obj, Error **errp) 
{
    D22IDeviceMachineState *s = D22_IDEVICE_MACHINE(obj);
    return g_strdup(s->devicetree_fn);
}

static void d22_machine_set_boot_devicetree(Object *obj, const char *value, Error **errp) 
{
    D22IDeviceMachineState *s = D22_IDEVICE_MACHINE(obj);
    g_strlcpy(s->devicetree_fn, value, sizeof(s->devicetree_fn));
}

static char *d22_machine_get_boot_ramdisk(Object *obj, Error **errp)
{
    D22IDeviceMachineState *s = D22_IDEVICE_MACHINE(obj);
    return g_strdup(s->ramdisk_fn);
}

static void d22_machine_set_boot_ramdisk(Object *obj, const char *value, Error **errp)
{
    D22IDeviceMachineState *s = D22_IDEVICE_MACHINE(obj);
    g_strlcpy(s->ramdisk_fn, value, sizeof(s->ramdisk_fn));
}

static char *d22_machine_get_boot_trustcache(Object *obj, Error **errp)
{
    D22IDeviceMachineState *s = D22_IDEVICE_MACHINE(obj);
    return g_strdup(s->trustcache_fn);
}

static void d22_machine_set_boot_trustcache(Object *obj, const char *value, Error **errp)
{
    D22IDeviceMachineState *s = D22_IDEVICE_MACHINE(obj);
    g_strlcpy(s->trustcache_fn, value, sizeof(s->trustcache_fn));
}

static char *d22_machine_get_nvram_file(Object *obj, Error **errp)
{
    D22IDeviceMachineState *s = D22_IDEVICE_MACHINE(obj);
    return g_strdup(s->nvram_fn);
}

static void d22_machine_set_nvram_file(Object *obj, const char *value, Error **errp)
{
    D22IDeviceMachineState *s = D22_IDEVICE_MACHINE(obj);
    g_strlcpy(s->nvram_fn, value, sizeof(s->nvram_fn));
}

static char *d22_machine_get_bootargs(Object *obj, Error **errp)
{
    D22IDeviceMachineState *s = D22_IDEVICE_MACHINE(obj);
    return g_strdup(s->bootargs);
}

static void d22_machine_set_bootargs(Object *obj, const char *value, Error **errp)
{
    D22IDeviceMachineState *s = D22_IDEVICE_MACHINE(obj);
    g_strlcpy(s->bootargs, value, sizeof(s->bootargs));
}

static char *d22_machine_get_ram_size(Object *obj, Error **errp)
{
    D22IDeviceMachineState *s = D22_IDEVICE_MACHINE(obj);
    uint64_t value = s->bootinfo.ram_size;
    char *ret = g_new(char, 32);
    snprintf(ret, 32, "%" PRIu64, value);
    return ret;
}

static void d22_machine_set_ram_size(Object *obj, const char *value, Error **errp)
{
    D22IDeviceMachineState *s = D22_IDEVICE_MACHINE(obj);
    uint64_t size = strtoull(value, NULL, 0);
    s->bootinfo.ram_size = size;
}

static char *d22_machine_get_ramfb(Object *obj, Error **errp)
{
    D22IDeviceMachineState *s = D22_IDEVICE_MACHINE(obj);
    return strdup(s->enable_ramfb ? "on" : "off");
}

static void d22_machine_set_ramfb(Object *obj, const char *value, Error **errp)
{
    D22IDeviceMachineState *s = D22_IDEVICE_MACHINE(obj);
    if (strcmp(value, "on") == 0) {
        s->enable_ramfb = 1;
    } else if (strcmp(value, "off") != 0) {
        s->enable_ramfb = 0;
    }
}

static void d22_instance_init(Object *obj) {
    object_property_add_str(obj, "kernelcache",
                            d22_machine_get_boot_kernel,
                            d22_machine_set_boot_kernel);
    object_property_set_description(obj, "kernelcache",
                                    "Path to XNU kernelcache");
    object_property_add_str(obj, "devicetree",
                            d22_machine_get_boot_devicetree,
                            d22_machine_set_boot_devicetree);
    object_property_add_str(obj, "ramdisk",
                            d22_machine_get_boot_ramdisk,
                            d22_machine_set_boot_ramdisk);
    object_property_add_str(obj, "trustcache",
                            d22_machine_get_boot_trustcache,
                            d22_machine_set_boot_trustcache);
    object_property_add_str(obj, "nvram",
                            d22_machine_get_nvram_file,
                            d22_machine_set_nvram_file);
    object_property_add_str(obj, "bootargs",
                            d22_machine_get_bootargs,
                            d22_machine_set_bootargs);
    object_property_add_str(obj, "ram-size",
                            d22_machine_get_ram_size,
                            d22_machine_set_ram_size);
    object_property_add_str(obj, "ramfb",
                            d22_machine_get_ramfb,
                            d22_machine_set_ramfb);
}

static const TypeInfo d22_machine_info = {
    .name = TYPE_D22_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(D22IDeviceMachineState),
    .class_size = sizeof(D22IDeviceMachineState),
    .class_init = d22_machine_class_init,
    .instance_init = d22_instance_init,
};

static void d22_machine_register_types(void) {
    type_register_static(&d22_machine_info);
}

type_init(d22_machine_register_types);
