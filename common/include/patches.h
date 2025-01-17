#ifndef patches_h
#define patches_h

#include <stdio.h>
#include <mach/mach.h>
#include <sys/types.h>

#include "exploit.h"

#define TTB_SIZE                4096
#define L1_SECT_S_BIT           (1 << 16)
#define L1_SECT_PROTO           (1 << 1)
#define L1_SECT_AP_URW          (1 << 10) | (1 << 11)
#define L1_SECT_APX             (1 << 15)
#define L1_SECT_DEFPROT         (L1_SECT_AP_URW | L1_SECT_APX)
#define L1_SECT_SORDER          (0)
#define L1_SECT_DEFCACHE        (L1_SECT_SORDER)
#define L1_PROTO_TTE(entry)     (entry | L1_SECT_S_BIT | L1_SECT_DEFPROT | L1_SECT_DEFCACHE)
#define L1_PAGE_PROTO           (1 << 0)
#define L1_COARSE_PT            (0xFFFFFC00)
#define PT_SIZE                 256
#define L2_PAGE_APX             (1 << 9)
#define BOOTARGS_STR            "cs_enforcement_disable=1 amfi_get_out_of_my_way=1"

#define wk16_exec(addr, val) { \
    if (patch_page_table(tte_virt, tte_phys, (addr & ~0xFFF)) != 0) goto done; \
    wk16(addr, val); \
}

#define wk32_exec(addr, val) { \
    if (patch_page_table(tte_virt, tte_phys, (addr & ~0xFFF)) != 0) goto done; \
    wk32(addr, val); \
}

typedef struct {
    uint32_t proc_enforce;
    uint32_t cs_enforcement_disable;
    uint32_t bootargs;
    uint32_t mount_common;
    uint32_t kernel_pmap;
    uint32_t csops;
    uint32_t sandbox_call_i_can_has_debugger;
    uint32_t i_can_has_debugger_1;
    uint32_t i_can_has_debugger_2;
    uint32_t vm_fault_enter_patch;
    uint32_t vm_map_enter_patch;
    uint32_t vm_map_protect_patch;
    uint32_t tfp0_patch;
    uint32_t container_required;
} patches_t;

int patch_kernel(kinfo_t *kinfo);

#endif /* patches_h */