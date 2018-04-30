#include "globals.h"
#include "errno.h"
#include "types.h"

#include "mm/mm.h"
#include "mm/tlb.h"
#include "mm/mman.h"
#include "mm/page.h"

#include "proc/proc.h"

#include "util/string.h"
#include "util/debug.h"

#include "fs/vnode.h"
#include "fs/vfs.h"
#include "fs/file.h"

#include "vm/vmmap.h"
#include "vm/mmap.h"

/*
 * This function implements the mmap(2) syscall, but only
 * supports the MAP_SHARED, MAP_PRIVATE, MAP_FIXED, and
 * MAP_ANON flags.
 *
 * Add a mapping to the current process's address space.
 * You need to do some error checking; see the ERRORS section
 * of the manpage for the problems you should anticipate.
 * After error checking most of the work of this function is
 * done by vmmap_map(), but remember to clear the TLB.
 */
int
do_mmap(void *addr, size_t len, int prot, int flags,
        int fd, off_t off, void **ret)
{
        if(len == 0) return -EINVAL;

        int map_type = flags & MAP_TYPE;
        if(!(map_type == MAP_SHARED || map_type == MAP_PRIVATE)) return -EINVAL;

        if(!PAGE_ALIGNED(off)) return -EINVAL;

        // if the flag is MAP_FIXED, the address should be provided and page aligned
        if((flags & MAP_FIXED) && addr == NULL) return -EINVAL;
        if (!(flags & MAP_ANON) && (flags & MAP_FIXED) && !PAGE_ALIGNED(addr)) return -EINVAL;
    
        if(addr != NULL && ((uint32_t) addr < USER_MEM_LOW || (uint32_t) addr >= USER_MEM_HIGH)) {
            return -EINVAL;
        }

        if(len > USER_MEM_HIGH) return -EINVAL;

        if(addr != NULL && (uint32_t) addr + len > USER_MEM_HIGH) return -EINVAL;

        vnode_t *vnode;

        if(flags & MAP_ANON) {
            vnode = NULL;
        } else {
            if(fd < 0 || fd >= NFILES || curproc->p_files[fd] == NULL) {
                return -EBADF;
            }

            file_t *file = curproc->p_files[fd];
            vnode = file->f_vnode;

            if((flags & MAP_PRIVATE) && !(file->f_mode & FMODE_READ)) {
                return -EACCES;
            }

            // ?
            if ((flags & MAP_SHARED) && (prot & PROT_WRITE) &&
                !((file->f_mode & FMODE_READ) && (file->f_mode & FMODE_WRITE))){
                return -EACCES;
            }
        }

        vmarea_t *vma;

        int map_res = vmmap_map(curproc->p_vmmap, vnode, ADDR_TO_PN(addr), 
                            (uint32_t)PAGE_ALIGN_UP(len) / PAGE_SIZE, prot, flags, off,
                            VMMAP_DIR_HILO, &vma);

        if(map_res < 0) {
            KASSERT(map_res == -ENOMEM);
        }

        if(map_res == 0) {
            if(ret != NULL) {
                *ret = PN_TO_ADDR(vma->vma_start);
            }

            /* unmap the page table entry and flush the corresponding TLB to
            *  clear the original cache, and when page fault, call pt_map()
            */
            pt_unmap_range(curproc->p_pagedir, (uintptr_t) PN_TO_ADDR(vma->vma_start),
               (uintptr_t) PN_TO_ADDR(vma->vma_start)
               + (uintptr_t) PAGE_ALIGN_UP(len));

            tlb_flush_range((uintptr_t) PN_TO_ADDR(vma->vma_start),
                (uint32_t) PAGE_ALIGN_UP(len) / PAGE_SIZE);
        }

        return map_res;
}


/*
 * This function implements the munmap(2) syscall.
 *
 * As with do_mmap() it should perform the required error checking,
 * before calling upon vmmap_remove() to do most of the work.
 * Remember to clear the TLB.
 */
int
do_munmap(void *addr, size_t len)
{
        if((uint32_t) addr < USER_MEM_LOW || USER_MEM_HIGH - (uint32_t) addr < len) {
            return -EINVAL;
        }

        if(len == 0) return -EINVAL;

        if(!PAGE_ALIGNED(addr)) return -EINVAL;

        int remove_res = vmmap_remove(curproc->p_vmmap, ADDR_TO_PN(addr), 
                                        (uint32_t)PAGE_ALIGN_UP(len) / PAGE_SIZE);

        /* unmapping the page table and flushing the TLB have been done in vmmap_remove */
        return remove_res;
}

