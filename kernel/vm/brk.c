#include "globals.h"
#include "errno.h"
#include "util/debug.h"

#include "mm/mm.h"
#include "mm/page.h"
#include "mm/mman.h"

#include "vm/mmap.h"
#include "vm/vmmap.h"

#include "proc/proc.h"

/*
 * This function implements the brk(2) system call.
 *
 * This routine manages the calling process's "break" -- the ending address
 * of the process's "dynamic" region (often also referred to as the "heap").
 * The current value of a process's break is maintained in the 'p_brk' member
 * of the proc_t structure that represents the process in question.
 *
 * The 'p_brk' and 'p_start_brk' members of a proc_t struct are initialized
 * by the loader. 'p_start_brk' is subsequently never modified; it always
 * holds the initial value of the break. Note that the starting break is
 * not necessarily page aligned!
 *
 * 'p_start_brk' is the lower limit of 'p_brk' (that is, setting the break
 * to any value less than 'p_start_brk' should be disallowed).
 *
 * The upper limit of 'p_brk' is defined by the minimum of (1) the
 * starting address of the next occuring mapping or (2) USER_MEM_HIGH.
 * That is, growth of the process break is limited only in that it cannot
 * overlap with/expand into an existing mapping or beyond the region of
 * the address space allocated for use by userland. (note the presence of
 * the 'vmmap_is_range_empty' function).
 *
 * The dynamic region should always be represented by at most ONE vmarea.
 * Note that vmareas only have page granularity, you will need to take this
 * into account when deciding how to set the mappings if p_brk or p_start_brk
 * is not page aligned.
 *
 * You are guaranteed that the process data/bss region is non-empty.
 * That is, if the starting brk is not page-aligned, its page has
 * read/write permissions.
 *
 * If addr is NULL, you should "return" the current break. We use this to
 * implement sbrk(0) without writing a separate syscall. Look in
 * user/libc/syscall.c if you're curious.
 *
 * You should support combined use of brk and mmap in the same process.
 *
 * Note that this function "returns" the new break through the "ret" argument.
 * Return 0 on success, -errno on failure.
 */
int
do_brk(void *addr, void **ret)
{
        KASSERT(ret != NULL);

        if(addr == NULL || addr == curproc->p_brk) {
            *ret = curproc->p_brk;
            return 0;
        }

        if((uint32_t) addr < (uint32_t) curproc->p_start_brk ||
            (uint32_t) addr > USER_MEM_HIGH) {
            return -ENOMEM;
        }

        uint32_t old_brk = (uint32_t) curproc->p_brk;

        uint32_t brk_endpn = ADDR_TO_PN(PAGE_ALIGN_UP(addr));
        uint32_t old_brk_endpn = ADDR_TO_PN(PAGE_ALIGN_UP(old_brk));

        /* if the pagenumber is not the same, we should modify the vmarea*/
        if(brk_endpn != old_brk_endpn) {
            if(brk_endpn < old_brk_endpn) {
                /* the new brk is smaller than old brk, so we should
                *  cut off the vmarea. */
                uint32_t npages = old_brk_endpn - brk_endpn;
                vmmap_remove(curproc->p_vmmap, brk_endpn, npages);
            } else {
                /* the new brk is greater than old brk, so we should
                *  extend the vmarea. */
                uint32_t npages = brk_endpn - old_brk_endpn;
                KASSERT(npages > 0);

                /* if this range is not empty */
                if(!vmmap_is_range_empty(curproc->p_vmmap, old_brk_endpn, npages)) {
                    return -ENOMEM;
                }

                uint32_t start_brk_endpn = ADDR_TO_PN(PAGE_ALIGN_UP(curproc->p_start_brk));
                vmarea_t *vma = vmmap_lookup(curproc->p_vmmap, start_brk_endpn);

                /* if there's no vmarea before, mmap a new one */
                if(vma == NULL) {
                    vmmap_map(curproc->p_vmmap, NULL, start_brk_endpn, brk_endpn - start_brk_endpn,
                                PROT_READ | PROT_WRITE, MAP_PRIVATE, 0, VMMAP_DIR_LOHI, &vma);
                } else {
                    KASSERT(brk_endpn >= vma->vma_end);
                    vma->vma_end = brk_endpn;
                }
            }
        }

        curproc->p_brk = addr;
        *ret = addr;
        return 0;
}
