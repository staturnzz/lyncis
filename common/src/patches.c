#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "common.h"
#include "io.h"
#include "offsets.h"
#include "memory.h"
#include "exploit.h"
#include "utils.h"
#include "patchfinder.h"
#include "patches.h"

static uint32_t tte_virt = 0;
static uint32_t tte_phys = 0;
static void *kernel_data = NULL;
static size_t kernel_data_size = 0xffe000;
static uint32_t kernel_base = 0;
static uint32_t *pmap_list = NULL;
static int pmap_count = 0;

int patch_pmap(uint32_t kernel_pmap) {
    uint32_t kernel_pmap_store = rk32(kernel_pmap);
    tte_virt = rk32(kernel_pmap_store);
    tte_phys = rk32(kernel_pmap_store+4);
    
    uint32_t i = 0;
    for (i = 0; i < TTB_SIZE; i++) {
        uint32_t addr = tte_virt + (i << 2);
        uint32_t entry = rk32(addr);
        if (entry == 0) continue;
        if ((entry & 0x3) == 1) {
            uint32_t lvl_pg_addr = (entry & (~0x3ff)) - tte_phys + tte_virt;
            for (int i = 0; i < 256; i++) {
                uint32_t sladdr  = lvl_pg_addr + (i << 2);
                uint32_t slentry = rk32(sladdr);
                if (slentry == 0) continue;
                
                uint32_t new_entry = slentry & (~0x200);
                if (slentry != new_entry) {
                    wk32(sladdr, new_entry);
                    pmap_list[pmap_count++] = sladdr;
                }
            }
            continue;
        }
        
        if ((entry & L1_SECT_PROTO) == 2) {
            uint32_t new_entry = L1_PROTO_TTE(entry);
            new_entry &= ~L1_SECT_APX;
            wk32(addr, new_entry);
        }
    }
    usleep(100000);
    return 0;
}

int patch_page_table(uint32_t tte_virt, uint32_t tte_phys, uint32_t page) {
    if (page < kernel_base) return -1;
    uint32_t i = page >> 20;
    uint32_t j = (page >> 12) & 0xFF;

    uint32_t addr = tte_virt + (i << 2);
    uint32_t entry = rk32(addr);
    if (entry == 0) return -1;

    if ((entry & L1_PAGE_PROTO) == L1_PAGE_PROTO) {
        uint32_t page_entry = ((entry & L1_COARSE_PT) - tte_phys) + tte_virt;
        uint32_t addr2 = page_entry + (j << 2);
        uint32_t entry2 = rk32(addr2);
        if (entry2 != 0) {
            uint32_t new_entry2 = (entry2 & (~L2_PAGE_APX));
            wk32(addr2, new_entry2);
        }
    } else if ((entry & L1_SECT_PROTO) == L1_SECT_PROTO) {
        uint32_t new_entry = L1_PROTO_TTE(entry);
        new_entry &= ~L1_SECT_APX;
        wk32(addr, new_entry);
    }
    usleep(10000);
    return 0;
}

uint32_t find_patch_offset(uint32_t (*func)(uint32_t, uint8_t *, size_t)) {
    uint32_t addr = func(kernel_base, kernel_data, kernel_data_size);
    if (addr <= 0xffff) return 0;
    return addr + kernel_base;
}

void set_bootargs(uint32_t bootargs_addr, char *bootargs) {
    size_t new_bootargs_len = strlen(bootargs) + 1;
    size_t bootargs_buf_len = (new_bootargs_len + 3) / 4 * 4;
    char bootargs_buf[bootargs_buf_len];
    strlcpy(bootargs_buf, bootargs, bootargs_buf_len);
    memset(bootargs_buf + new_bootargs_len, 0, bootargs_buf_len - new_bootargs_len);
    
    uint32_t str_addr = rk32(bootargs_addr) + 0x38;
    kwrite(str_addr, bootargs_buf, bootargs_buf_len);
    usleep(10000);
}

int patch_kernel(kinfo_t *kinfo) {
    patches_t *patches = calloc(1, sizeof(patches_t));
    if ((pmap_list = calloc(1, TTB_SIZE * sizeof(uint32_t))) == NULL) goto done;
    kernel_base = kinfo->kernel_base;
    int rv = -1;

    if ((kernel_data = calloc(1, kernel_data_size)) == NULL) goto done;
    kread(kernel_base, kernel_data, kernel_data_size);

    if ((patches->proc_enforce = find_patch_offset(find_proc_enforce)) == 0) goto done;
    if ((patches->cs_enforcement_disable = find_patch_offset(find_cs_enforcement_disable_amfi)) == 0) goto done;
    if ((patches->bootargs = find_patch_offset(find_p_bootargs)) == 0) goto done;
    if ((patches->mount_common = find_patch_offset(find_mount)) == 0) goto done;
    if ((patches->kernel_pmap = find_patch_offset(find_pmap_location)) == 0) goto done;
    if ((patches->csops = find_patch_offset(find_csops)) == 0) goto done;
    if ((patches->sandbox_call_i_can_has_debugger = find_patch_offset(find_sandbox_call_i_can_has_debugger)) == 0) goto done;
    if ((patches->i_can_has_debugger_1 = find_patch_offset(find_i_can_has_debugger_1)) == 0) goto done;
    if ((patches->i_can_has_debugger_2 = find_patch_offset(find_i_can_has_debugger_2)) == 0) goto done;
    if ((patches->vm_fault_enter_patch = find_patch_offset(find_vm_fault_enter_patch)) == 0) goto done;
    if ((patches->vm_map_enter_patch = find_patch_offset(find_vm_map_enter_patch)) == 0) goto done;
    if ((patches->vm_map_protect_patch = find_patch_offset(find_vm_map_protect_patch)) == 0) goto done;
    if ((patches->tfp0_patch = find_patch_offset(find_tfp0_patch)) == 0) goto done;    
    if ((patches->container_required = find_patch_offset(find_container_required_patch)) == 0) goto done;
    if (patch_pmap(patches->kernel_pmap) != 0) goto done;

    set_bootargs(patches->bootargs, BOOTARGS_STR);
    wk32(patches->container_required, 'haxx');
    
    wk32(patches->proc_enforce, 0);
    wk8(patches->cs_enforcement_disable, 1);
    wk8(patches->cs_enforcement_disable-4, 1);
    wk32(patches->i_can_has_debugger_1, 1);
    wk32(patches->i_can_has_debugger_2, 1);

    wk32_exec(patches->mount_common, 0x0501F025);
    wk32_exec(patches->tfp0_patch, 0xbf00bf00);
    wk32_exec(patches->sandbox_call_i_can_has_debugger, 0xbf00bf00);

    if (rk32(patches->vm_fault_enter_patch) == 0xd10f) {
        wk32_exec(patches->vm_fault_enter_patch, 0x2201bf00);
    } else {
        wk32_exec(patches->vm_fault_enter_patch, 0x0b00f04f);
        wk16_exec(patches->vm_fault_enter_patch+0xc, 0xbf00);
    }
    
    wk32_exec(patches->vm_map_protect_patch, 0xbf00bf00);
    wk16_exec(patches->vm_map_enter_patch, 0x29ff);
    wk32_exec(patches->csops, 0xbf00bf00);
    rv = 0;

done:
    if (patches != NULL) free(patches);
    if (kernel_data != NULL) free(kernel_data);
    if (pmap_list != NULL) free(pmap_list);
    return rv;
}

