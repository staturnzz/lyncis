#ifndef patchfinder_h
#define patchfinder_h

#include <stdint.h>
#include <string.h>

struct find_search_mask {
	uint16_t mask;
	uint16_t value;
};

uint32_t find_pmap_location(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_proc_enforce(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_cs_enforcement_disable_amfi(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_i_can_has_debugger_1(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_i_can_has_debugger_2(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vm_fault_enter_patch(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vm_map_enter_patch(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vm_map_protect_patch(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_tfp0_patch(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_p_bootargs(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_csops(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_sandbox_call_i_can_has_debugger(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_mount(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_container_required_patch(uint32_t region, uint8_t *kdata, size_t ksize);

#endif /* patchfinder_h */
