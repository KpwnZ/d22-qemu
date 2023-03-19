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

#ifndef __APPLE__

typedef int32_t 	integer_t;
typedef integer_t	cpu_type_t;
typedef integer_t	cpu_subtype_t;
typedef integer_t	cpu_threadtype_t;
typedef int			vm_prot_t;

/* Constant for the magic field of the mach_header (32-bit architectures) */
#define	MH_MAGIC	0xfeedface	/* the mach magic number */
#define MH_CIGAM	NXSwapInt(MH_MAGIC)

/* Constant for the magic field of the mach_header_64 (64-bit architectures) */
#define MH_MAGIC_64	0xfeedfacf	/* the 64-bit mach magic number */
#define MH_CIGAM_64	NXSwapInt(MH_MAGIC_64)

/* Constants for the cmd field of new load commands, the type */
#define LC_SEGMENT_64	0x19	/* 64-bit segment of this file to be mapped */
#define LC_ROUTINES_64	0x1a	/* 64-bit image routines */

struct mach_header_64 {
	uint32_t	magic;		/* mach magic number identifier */
	cpu_type_t	cputype;	/* cpu specifier */
	cpu_subtype_t	cpusubtype;	/* machine specifier */
	uint32_t	filetype;	/* type of file */
	uint32_t	ncmds;		/* number of load commands */
	uint32_t	sizeofcmds;	/* the size of all the load commands */
	uint32_t	flags;		/* flags */
	uint32_t	reserved;	/* reserved */
};

struct load_command {
    uint32_t cmd;               /* type of load command */
    uint32_t cmdsize;           /* total size of command in bytes */
};

/* Constants for the cmd field of all load commands, the type */
#define	LC_SEGMENT	0x1	/* segment of this file to be mapped */
#define	LC_SYMTAB	0x2	/* link-edit stab symbol table info */
#define	LC_SYMSEG	0x3	/* link-edit gdb symbol table info (obsolete) */
#define	LC_THREAD	0x4	/* thread */
#define	LC_UNIXTHREAD	0x5	/* unix thread (includes a stack) */
#define	LC_LOADFVMLIB	0x6	/* load a specified fixed VM shared library */
#define	LC_IDFVMLIB	0x7	/* fixed VM shared library identification */
#define	LC_IDENT	0x8	/* object identification info (obsolete) */
#define LC_FVMFILE	0x9	/* fixed VM file inclusion (internal use) */
#define LC_PREPAGE      0xa     /* prepage command (internal use) */
#define	LC_DYSYMTAB	0xb	/* dynamic link-edit symbol table info */
#define	LC_LOAD_DYLIB	0xc	/* load a dynamicly linked shared library */
#define	LC_ID_DYLIB	0xd	/* dynamicly linked shared lib identification */
#define LC_LOAD_DYLINKER 0xe	/* load a dynamic linker */
#define LC_ID_DYLINKER	0xf	/* dynamic linker identification */
#define	LC_PREBOUND_DYLIB 0x10	/* modules prebound for a dynamicly */
				/*  linked shared library */

struct segment_command_64 {	/* for 64-bit architectures */
	uint32_t	cmd;		/* LC_SEGMENT_64 */
	uint32_t	cmdsize;	/* includes sizeof section_64 structs */
	char		segname[16];	/* segment name */
	uint64_t	vmaddr;		/* memory address of this segment */
	uint64_t	vmsize;		/* memory size of this segment */
	uint64_t	fileoff;	/* file offset of this segment */
	uint64_t	filesize;	/* amount to map from the file */
	vm_prot_t	maxprot;	/* maximum VM protection */
	vm_prot_t	initprot;	/* initial VM protection */
	uint32_t	nsects;		/* number of sections in segment */
	uint32_t	flags;		/* flags */
};

#endif

#endif