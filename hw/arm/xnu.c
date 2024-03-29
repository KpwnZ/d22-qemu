#include <libfdt.h>
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/datadir.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include <libfdt.h>
#include "hw/arm/boot.h"
#include "hw/arm/linux-boot-if.h"
#include "sysemu/kvm.h"
#include "sysemu/sysemu.h"
#include "sysemu/numa.h"
#include "sysemu/reset.h"
#include "hw/loader.h"
#include "elf.h"
#include "sysemu/device_tree.h"
#include "qemu/config-file.h"
#include "qemu/option.h"
#include "qemu/units.h"
#ifdef __APPLE__
#include <mach-o/loader.h>
#endif
#include "hw/arm/xnu.h"
#include "hw/arm/boot.h"
#include "hw/loader.h"
#include "exec/memory.h"
#include "hw/boards.h"
#include "hw/arm/xnumem.h"
#include "hw/arm/xnudt.h"
#include "hw/arm/d22-idevice.h"

#define DEBUG_XNU_DEVICETREE
// #undef DEBUG_XNU_DEVICETREE

inline uint64_t va2pa(uint64_t va, struct arm_boot_info *info) {
    return (va & 0x3fffffff) + info->loader_start;
}

// from alephsecurity
static void macho_do_find_highest_lowest(struct mach_header_64 *mh, uint64_t *lowaddr,
                                         uint64_t *highaddr) {
    struct load_command* cmd = (struct load_command*)((uint8_t*)mh + sizeof(struct mach_header_64));
    uint64_t low_addr_temp = ~0;
    uint64_t high_addr_temp = 0;
    for (unsigned int index = 0; index < mh->ncmds; index++) {
        switch (cmd->cmd) {
            case LC_SEGMENT_64: {
                struct segment_command_64 *command =
                                        (struct segment_command_64 *)cmd;
                if (command->vmaddr < low_addr_temp) {
                    low_addr_temp = command->vmaddr;
                }
                if (command->vmaddr + command->vmsize > high_addr_temp) {
                    high_addr_temp = command->vmaddr + command->vmsize;
                }
                break;
            }
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    *lowaddr = low_addr_temp;
    *highaddr = high_addr_temp;
}

static 
void macho_find_highest_lowest(const char *data, hwaddr *lowest,
                               hwaddr *highest) {
    uint8_t *kdata = (uint8_t *)data;
    while (*(uint32_t *)kdata != 0xFEEDFACF) {
        kdata += 0x4;
    }
    struct mach_header_64 *mh = (struct mach_header_64 *)kdata;
    macho_do_find_highest_lowest(mh, lowest, highest);
}

static 
void macho_file_highest_lowest(const char *data, hwaddr phys_base,
                               hwaddr *virt_base, hwaddr *lowest,
                               hwaddr *highest) 
{
    macho_find_highest_lowest(data, lowest, highest);
    *virt_base = align64low(*lowest) & (~0x3fffffff);
}

static size_t arm_load_xnu_bootargs(struct arm_boot_info *info, AddressSpace *as, MemoryRegion *mem,
                                    uint64_t bootargs_addr, uint64_t virt_base,
                                    uint64_t phys_base, uint64_t top_of_kernel_data,
                                    uint64_t dtb_address, uint64_t dtb_size, uint64_t ram_size,
                                    MachineState *m) {
    D22IDeviceMachineState *d22 = D22_IDEVICE_MACHINE(m);
    d22->boot_args.Revision = kXNUBootArgsRevision2;
    d22->boot_args.Version = kXNUBootArgsVersion2;
    d22->boot_args.virtBase = virt_base;
    d22->boot_args.physBase = phys_base;
    // top of kernel data (kernel, dtb, any ramdisk) + boot args size + padding to 16k
    d22->boot_args.topOfKernelData = ((top_of_kernel_data + sizeof(d22->boot_args)) + 0xffffull) & ~0xffffull;
    // todo: video, machine type, cmdline, flags
    strncpy(d22->boot_args.CommandLine, info->kernel_cmdline, sizeof(d22->boot_args.CommandLine));
    d22->boot_args.deviceTreeP = (void *)dtb_address;
    d22->boot_args.deviceTreeLength = dtb_size;
    d22->boot_args.memSizeActual = 0;
    rom_add_blob_fixed_as("xnu_boot_args", &d22->boot_args, sizeof(d22->boot_args), bootargs_addr, as);
    return sizeof(d22->boot_args);
}

XNUDTNode *arm_load_xnu_devicetree(gchar *blob) {

	XNUDTNode *root = arm_do_parse_xnu_devicetree(&blob);
#ifdef DEBUG_XNU_DEVICETREE
	printf("[+] loaded root node with %u properties and %d children\n", root->nprops, root->nchildren);
#endif  // DEBUG_XNU_DEVICETREE
    return root;
}

static bool keep_compatible(const char *name) {
    const char *keep_list[] = {
        "aic", "aic-timebase", "uart",
        "disp0"
    };
    for (int i = 0; i < sizeof(keep_list) / sizeof(keep_list[0]); i++) {
        int len = strlen(keep_list[i]);
        if (strncmp(name, keep_list[i], len) == 0) {
            return true;
        }
    }
    return false;
}

static gchar *preprocess_devicetree(
    XNUDTNode *root, uint64_t *dt_len, 
    uint64_t ramdisk_addr, uint64_t ramdisk_size, const uint8_t *nvram_proxy_data) {
    // set cpu0's "timebase-frequency" property to freq
    uint64_t freq = 2000000;
    XNUDTNode *node = arm_get_xnu_devicetree_node_by_path(root, "/device-tree/cpus/cpu0");
    assert(node != NULL);
    XNUDTProp *prop = arm_get_xnu_devicetree_prop(node, "timebase-frequency");
    if (prop) {
        memcpy(prop->value, &freq, sizeof(freq));
    } else {
        arm_add_xnu_devicetree_prop(root, "timebase-frequency", sizeof(freq), (char *)&freq, "/device-tree/cpus/cpu0");
    }
    prop = arm_get_xnu_devicetree_prop(node, "fixed-frequency");
    if (prop) {
        memcpy(prop->value, &freq, sizeof(freq));
    } else {
        arm_add_xnu_devicetree_prop(root, "fixed-frequency", sizeof(freq), (char *)&freq, "/device-tree/cpus/cpu0");
    }

    prop = arm_search_xnu_devicetree_prop_by_name(root, "secure-root-prefix");
    memcpy(prop->name, "no-secure-root-prefix", kPropNameLength);
    
    uint64_t seed[8] = {0x12345678, 0x12345678, 0x12345678, 0x12345678,
                        0x12345678, 0x12345678, 0x12345678, 0x12345678};
    node = arm_get_xnu_devicetree_node_by_path(root, "/device-tree/chosen");
    assert(node != NULL);
    prop = arm_get_xnu_devicetree_prop(node, "random-seed");
    if (prop) {
        memcpy(prop->value, seed, sizeof(seed));
    } else {
        arm_add_xnu_devicetree_prop(root, "random-seed", sizeof(seed), (char *)seed, "/device-tree/chosen");
    }

    node = arm_get_xnu_devicetree_node_by_path(root, "/device-tree/arm-io/uart0");
    assert(node != NULL);
    
    prop = arm_get_xnu_devicetree_prop(node, "reg");
    assert(prop != NULL);

    uint32_t display_rotation = 0, display_scale = 1;
    node = arm_get_xnu_devicetree_node_by_path(root, "/device-tree/chosen");
    prop = arm_get_xnu_devicetree_prop(node, "display-rotation");
    if (prop) {
        memcpy(&display_rotation, prop->value, sizeof(display_rotation));
    } else {
        arm_add_xnu_devicetree_prop(root, "display-rotation", sizeof(display_rotation), (char *)&display_rotation, "/device-tree/chosen");
    }

    prop = arm_get_xnu_devicetree_prop(node, "display-scale");
    if (prop) {
        memcpy(&display_scale, prop->value, sizeof(display_scale));
    } else {
        arm_add_xnu_devicetree_prop(root, "display-scale", sizeof(display_scale), (char *)&display_scale, "/device-tree/chosen");
    }

    prop = arm_get_xnu_devicetree_prop(node, "nvram-proxy-data");
    memset(prop->value, 0, prop->length);
    memcpy(prop->value, nvram_proxy_data, 8192);
    prop = arm_get_xnu_devicetree_prop(node, "nvram-total-size");
    if (!prop) {
        uint64_t data = 8192;
        arm_add_xnu_devicetree_prop(root, "nvram-total-size", sizeof(uint32_t), (char *)&data, "/device-tree/chosen");
    } else { *(uint32_t *)prop->value = 8192; }

    uint32_t data = 1;
    arm_add_xnu_devicetree_prop(root, "security-domain", sizeof(data), (char *)&data, "/device-tree/chosen");
    arm_add_xnu_devicetree_prop(root, "chip-epoch", sizeof(data), (char *)&data, "/device-tree/chosen");
    data = 0;
    arm_add_xnu_devicetree_prop(root, "debug-enabled", sizeof(data), (char *)&data, "/device-tree/chosen");

    node = arm_get_xnu_devicetree_node_by_path(root, "/device-tree/arm-io/aic");
    // prop = arm_get_xnu_devicetree_prop(node, "ipid-mask");
    // prop->length = 0;

    node = arm_get_xnu_devicetree_node_by_path(root, "/device-tree/arm-io/pmgr");
    prop = arm_get_xnu_devicetree_prop(node, "compatible");
    memset(prop->value, 0, prop->length);

    node = arm_get_xnu_devicetree_node_by_path(root, "/device-tree/arm-io");
    prop = arm_get_xnu_devicetree_prop(node, "compatible");
    for (GList *l = node->children; l != NULL; l = l->next) {
        XNUDTNode *child = (XNUDTNode *)l->data;
        if (!child) break;
        XNUDTProp *name = arm_get_xnu_devicetree_prop(child, "name");
        if (name) {
            if (!keep_compatible((const char *)name->value)) {
                XNUDTProp *comp = arm_get_xnu_devicetree_prop(child, "compatible");
                if (comp) {
                    memset(comp->value, 0, comp->length);
                }
            }
        }
    }

    data = 1;
    node = arm_get_xnu_devicetree_node_by_path(root, "/device-tree/defaults");
    arm_add_xnu_devicetree_prop(root, "no-effaceable-storage", sizeof(data), (char *)&data, "/device-tree/defaults");

    uint64_t rd[2] = {ramdisk_addr, ramdisk_size};
    node = arm_get_xnu_devicetree_node_by_path(root, "/device-tree/chosen/memory-map");
    arm_add_xnu_devicetree_prop(root, "RAMDisk", sizeof(rd), (char *)rd, "/device-tree/chosen/memory-map");

    node = arm_get_xnu_devicetree_node_by_path(root, "/device-tree/chosen");
    prop = arm_get_xnu_devicetree_prop(node, "firmware-version");
    if (prop) {
        strcpy((char *)prop->value, "D22-QEMU loader");
    } else {
        arm_add_xnu_devicetree_prop(root, "firmware-version", strlen("D22-QEMU loader") + 1, "D22-QEMU loader", "/device-tree/chosen");
    }
    
    // now write the device tree to memory
    uint8_t *dtb = NULL;
    arm_write_devicetree_to_memory(root, &dtb, dt_len);
    printf("[+] new devicetree size: 0x%llx\n", *dt_len);

    return (gchar *)dtb;
}

#define DEBUG_XEMU
int64_t xnu_init_memory(struct arm_boot_info *info,
                               MachineState *m,
                               XNUDTNode *devicetree,
                               const uint8_t *nvram_proxy_data,
                               hwaddr *pentry,
                               AddressSpace *as,
							   MemoryRegion *sysmem,
							   hwaddr *pc_addr,
							   hwaddr *bootargs_paddr) {

#ifdef DEBUG_XEMU
    printf("[*] %s arm_load_macho: %s\n", __PRETTY_FUNCTION__, info->kernel_filename);
#endif
    D22IDeviceMachineState *d22 = D22_IDEVICE_MACHINE(m);
    // hwaddr kernel_load_offset = 0;
    hwaddr mem_base = info->loader_start;
    gchar *data = NULL;
    uint8_t *rom_buf = NULL;
    gsize len;
    int ismacho = 0;
    uint64_t virt_base = 0;
    uint64_t phys_base = mem_base;
	uint64_t phys_ptr = phys_base;
	uint64_t used_ram = 0;
    uint64_t low = 0;
    uint64_t high = 0;

    g_file_get_contents(info->kernel_filename, &data, &len, NULL);
    gchar *macho_hdr = data;
    if(len <= 0) { exit(0); }
    while (*(uint32_t *)data != 0xFEEDFACF) {
        data += 0x4;
    }
    ismacho = *(uint32_t *)data == 0xFEEDFACF;
    if (!ismacho) {
        fprintf(stderr, "[!] invalid file format\n");
        return -1;
    }
    struct mach_header_64 *mh = (struct mach_header_64 *)data;
    struct load_command *cmds = (struct load_command *)((char *)mh + sizeof(struct mach_header_64));
    uint32_t ncmds = mh->ncmds;
    uint64_t pc = 0;
    macho_file_highest_lowest(data, info->loader_start,
                              &virt_base, &low, &high);
    uint64_t size = high - low;
    set_g_virt_base(virt_base);
    set_g_phys_base(info->loader_start);

    printf("[*] arm_load_macho: low: 0x%llx, high: 0x%llx, size: 0x%llx\n", low, high, size);

    // (2) copy kernel data to rom_buf
    uint64_t rom_buf_size = align64(high) - low;
    rom_buf = g_malloc0(rom_buf_size);
    struct load_command *cmd = cmds;
    for (int i = 0; i < ncmds; ++i) {
        if (cmd->cmd == LC_SEGMENT_64) {

#ifdef DEBUG_XEMU
            printf("[+] found LC_SEGMENT_64\n");
#endif

            struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
            memcpy(rom_buf + seg->vmaddr - low, data + seg->fileoff, seg->filesize);
#ifdef DEBUG_XEMU
            printf("[*] seg->vmaddr: 0x%llx, seg->filesize: 0x%llx\n", seg->vmaddr, seg->filesize);
#endif
        } else if (cmd->cmd == LC_UNIXTHREAD) {

#ifdef DEBUG_XEMU
            printf("[+] found LC_UNIXTHREAD\n");
#endif
            // thread_command_t *thread = (thread_command_t *)cmd;
            /* 
            struct thread_command {
                32 bit cmd, 32 bit cmdsize
                32 bit flavor, 32 bit count
                reg: x0-x28, fp, lr, sp, pc, cpsr
            }
            */
            pc = *(uint64_t *)(((char *)cmd) + 0x10 + 0x8 * 32);

#ifdef DEBUG_XEMU
            printf("[+] pc = 0x%llx\n", pc);
#endif
        }
        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }

    // load trust cache
    hwaddr rom_base = vtop_bases(low, phys_base, virt_base);
    uint64_t tcaddr = 0;
    gsize tcsize = 0;
    gchar *tcdata;
    g_file_get_contents(d22->trustcache_fn, &tcdata, &tcsize, NULL);
    gchar *tc_kernel_data = g_malloc0(tcsize + 8);
    *(uint32_t *)tc_kernel_data = 1;
    *(uint32_t *)(tc_kernel_data + 4) = 8;
    memcpy(tc_kernel_data + 8, tcdata, tcsize);
    tcsize += 8;
    tcaddr = align64(rom_base - tcsize - 0x4000);
    rom_add_blob_fixed_as("xnu.trustcache", tc_kernel_data, tcsize, tcaddr, as);
    g_free(tcdata);
    g_free(tc_kernel_data);
    printf("[*] trustcache addr: 0x%llx, size: 0x%lx\n", tcaddr, tcsize);
    uint64_t tc_dt_prop[2] = { tcaddr, tcsize };
    arm_add_xnu_devicetree_prop(devicetree, "TrustCache", sizeof(tc_dt_prop), (char *)tc_dt_prop, "/device-tree/chosen/memory-map");

    // (3) mask the address
    printf("[*] loader start: 0x%llx\n", info->loader_start);
    pc = vtop_bases(pc, phys_base, virt_base);
	*pc_addr = pc;
    printf("[*] kernel phy base: 0x%llx\n", rom_base);
    rom_add_blob_fixed_as("xnu.kernel", rom_buf, size, rom_base, as);
    g_free(macho_hdr);
    g_free(rom_buf);
    // allocate_and_copy(sysmem, as, "macho", rom_base, size, rom_buf);
	used_ram += (align64(high) - low);

    phys_ptr = (align64(vtop_bases(high, phys_base, virt_base)));
    // uint64_t offset = high;
    // printf("[*] phys_ptr: 0x%llx, dt_addr: 0x%llx\n", phys_ptr, offset);
    
    uint64_t ramdisk_addr = 0;
	gsize ramdisk_size = 0;
    gchar *ramdisk_data = NULL;
    if(info->initrd_filename) {
		ramdisk_addr = phys_ptr;
        g_file_get_contents(info->initrd_filename, &ramdisk_data, &ramdisk_size, NULL);
        rom_add_blob_fixed_as("xnu.ramdisk", ramdisk_data, ramdisk_size, phys_ptr, as);
        g_free(ramdisk_data);
        phys_ptr += align64(ramdisk_size + 0x30000);
    }

    gchar *dt_data = NULL;
    uint64_t dtb_va = ptov_static(phys_ptr);
    uint64_t dt_len = 0;

    XNUDTNode *root = devicetree;
    gchar *new_dt_data = preprocess_devicetree(root, (uint64_t *)&dt_len, ramdisk_addr, ramdisk_size, nvram_proxy_data);
    rom_add_blob_fixed_as("xnu.dtb", new_dt_data, dt_len, phys_ptr, as);
    g_free(dt_data);

    phys_ptr += (align64(dt_len));
    used_ram += (align64(dt_len));

#ifdef DEBUG_XEMU
	printf("[*] load bootargs\n");
#endif
	uint64_t bootargs_pa = phys_ptr;
    used_ram += align64(sizeof(struct xnu_boot_args));
    *bootargs_paddr = bootargs_pa;
    phys_ptr += align64(sizeof(struct xnu_boot_args) + 0x400000);

    arm_load_xnu_bootargs(info,
                          as,
                          sysmem,
                          bootargs_pa,
                          virt_base,
                          info->loader_start,
                          phys_ptr,  // top of kernel data
                          dtb_va,
                          dt_len,
                          info->ram_size, m);
    phys_base += (sizeof(struct xnu_boot_args) + 0xffffull) & ~0xffffull;
    

	printf("[*] arm_load_macho: done\n");
    return high - low;
    // return ret;
}
