#ifndef __ASM_PMAP_H__
#define __ASM_PMAP_H__

#include <xen/mm.h>

#include <asm/fixmap.h>

static inline void arch_pmap_map(unsigned int slot, mfn_t mfn)
{
    l1_pgentry_t *pl1e;
    void *va = fix_to_virt(slot);

    pl1e = &l1_fixmap[l1_table_offset((unsigned long)va)];
    l1e_write_atomic(pl1e, l1e_from_mfn(mfn, PAGE_HYPERVISOR));
}

static inline void arch_pmap_unmap(unsigned int slot)
{
    l1_pgentry_t *pl1e;
    void *va = fix_to_virt(slot);

    pl1e = &l1_fixmap[l1_table_offset((unsigned long)va)];
    l1e_write_atomic(pl1e, l1e_empty());
    flush_tlb_one_local(va);
}

#endif /* __ASM_PMAP_H__ */
