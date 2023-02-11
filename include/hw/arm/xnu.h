#ifndef HW_ARM_XNU_H
#define HW_ARM_XNU_H

#include "hw/arm/boot.h"
#include "hw/arm/xnumem.h"

struct XNU_Boot_Video {
	unsigned long   v_baseAddr;     /* Base address of video memory */
	unsigned long   v_display;      /* Display Code (if Applicable */
	unsigned long   v_rowBytes;     /* Number of bytes per pixel row */
	unsigned long   v_width;        /* Width */
	unsigned long   v_height;       /* Height */
	unsigned long   v_depth;        /* Pixel Depth and other parameters */
};

#define kXNUBootVideoDepthMask             (0xFF)
#define kXNUBootVideoDepthDepthShift       (0)
#define kXNUBootVideoDepthRotateShift      (8)
#define kXNUBootVideoDepthScaleShift       (16)
#define kXNUBootVideoDepthBootRotateShift  (24)

#define kBootFlagsDarkBoot              (1ULL << 0)

typedef struct Boot_Video       Boot_Video;

/* Boot argument structure - passed into Mach kernel at boot time.
 */
#define kXNUBootArgsRevision               1
#define kXNUBootArgsRevision2              2       /* added boot_args.bootFlags */
#define kXNUBootArgsVersion1               1
#define kXNUBootArgsVersion2               2

typedef struct xnu_boot_args {
	uint16_t                Revision;                       /* Revision of boot_args structure */
	uint16_t                Version;                        /* Version of boot_args structure */
	uint64_t                virtBase;                       /* Virtual base of memory */
	uint64_t                physBase;                       /* Physical base of memory */
	uint64_t                memSize;                        /* Size of memory */
	uint64_t                topOfKernelData;        /* Highest physical address used in kernel data area */
	struct XNU_Boot_Video   Video;                          /* Video Information */
	uint32_t                machineType;            /* Machine Type */
	void                    *deviceTreeP;           /* Base of flattened device tree */
	uint32_t                deviceTreeLength;       /* Length of flattened tree */
	char                    CommandLine[256];  /* Passed in command line */
	uint64_t                bootFlags;              /* Additional flags specified by the bootloader */
	uint64_t                memSizeActual;          /* Actual size of memory */
} boot_args;

#define kPropNameLength 32

#define get_member_ptr(s, e, ptr, name) \
    ((e *)(((char *)(ptr)) + offsetof(s, name)))

typedef struct __attribute__((packed, aligned(1))) {
    uint8_t name[kPropNameLength];
    uint32_t length;
    uint8_t *value;
} XNUDTProp;

typedef struct {
    uint32_t nprops;
    uint32_t nchildren;
    GList *properties;
    GList *children;
} XNUDTNode;

// convert virtual address to physical address
uint64_t va2pa(uint64_t va, struct arm_boot_info *info);
int64_t arm_init_memory(struct arm_boot_info *info,
                        hwaddr *pentry,
                        AddressSpace *as,
                        MemoryRegion *sysmem,
                        hwaddr *pc_addr,
                        hwaddr *bootarg_paddr);
#endif