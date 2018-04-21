#include "types.h"
#include "globals.h"
#include "errno.h"

#include "util/debug.h"
#include "util/string.h"

#include "proc/proc.h"
#include "proc/kthread.h"

#include "mm/mm.h"
#include "mm/mman.h"
#include "mm/page.h"
#include "mm/pframe.h"
#include "mm/mmobj.h"
#include "mm/pagetable.h"
#include "mm/tlb.h"

#include "fs/file.h"
#include "fs/vnode.h"

#include "vm/shadow.h"
#include "vm/vmmap.h"

#include "api/exec.h"

#include "main/interrupt.h"

/* Pushes the appropriate things onto the kernel stack of a newly forked thread
 * so that it can begin execution in userland_entry.
 * regs: registers the new thread should have on execution
 * kstack: location of the new thread's kernel stack
 * Returns the new stack pointer on success. */
static uint32_t
fork_setup_stack(const regs_t *regs, void *kstack)
{
        /* Pointer argument and dummy return address, and userland dummy return
         * address */
        uint32_t esp = ((uint32_t) kstack) + DEFAULT_STACK_SIZE - (sizeof(regs_t) + 12);
        *(void **)(esp + 4) = (void *)(esp + 8); /* Set the argument to point to location of struct on stack */
        memcpy((void *)(esp + 8), regs, sizeof(regs_t)); /* Copy over struct */
        return esp;
}

static void setup_shadow_obj(vmarea_t *vma, mmobj_t *shadow_obj){
    mmobj_t *bottom_obj = mmobj_bottom_obj(vma->vma_obj);

    KASSERT(bottom_obj->mmo_shadowed == NULL);

    shadow_obj->mmo_un.mmo_bottom_obj = bottom_obj;
    bottom_obj->mmo_ops->ref(bottom_obj);

    shadow_obj->mmo_shadowed = vma->vma_obj;

    if (list_link_is_linked(&vma->vma_olink)){
        list_remove(&vma->vma_olink);
    }

    list_insert_tail(&bottom_obj->mmo_un.mmo_vmas, &vma->vma_olink);

    /* shadow_obj already has a reference from before */
    vma->vma_obj = shadow_obj;
}


static void
vmmap_revert(list_t *old_vma_list, list_t *new_vma_list) {
    list_link_t *old_cur = old_vma_list->l_next;
    list_link_t *new_cur = new_vma_list->l_next;

    while(old_cur != old_vma_list) {
        vmarea_t *oldvma = list_item(old_cur, vmarea_t, vma_plink);
        vmarea_t *newvma = list_item(new_cur, vmarea_t, vma_plink);

        if(newvma->vma_obj == NULL) return;

        if((oldvma->vma_flags & MAP_TYPE) == MAP_PRIVATE) {
            KASSERT((newvma->vma_flags & MAP_TYPE) == MAP_PRIVATE);
            KASSERT(newvma->vma_obj->mmo_shadowed != NULL);
            KASSERT(oldvma->vma_obj->mmo_shadowed != NULL);

            mmobj_t *old_mmobj = oldvma->vma_obj->mmo_shadowed;
            old_mmobj->mmo_ops->ref(old_mmobj);

            oldvma->vma_obj->mmo_ops->put(oldvma->vma_obj);
            oldvma->vma_obj = old_mmobj;
        }

        old_cur = old_vma_list->l_next;
        new_cur = new_vma_list->l_next;
    }

    KASSERT(new_cur == new_vma_list);
}

static int
copy_vmmap(proc_t *p) {
    vmmap_t *new_vmmap = vmmap_clone(curproc->p_vmmap);

    if(new_vmmap == NULL) {
        return -ENOMEM;
    }

    new_vmmap->vmm_proc = p;

    list_t *old_vma_list = curproc->p_vmmap->vmm_list;
    list_t *new_vma_list = p->vmm_list;

    list_link_t *old_cur = old_vma_list->l_next;
    list_link_t *new_cur = new_vma_list->l_next;

    int err = 0;
    while(old_cur != old_vma_list && err == 0) {
        vmarea_t *oldvma = list_item(old_cur, vmarea_t, vma_plink);
        vmarea_t *newvma = list_item(new_cur, vmarea_t, vma_plink);

        /* set up vmobj and increment refcount */
        newvma->vma_obj = oldvma->vma_obj;
        newvma->vma_obj->mmo_ops->ref(newvma->vma_obj);

        int map_type = oldvma->vma_flags & MAP_TYPE;
        KASSERT(map_type == MAP_PRIVATE || map_type == MAP_SHARED);

        /* if the map type is private, set up shadow object */
        if(map_type == MAP_PRIVATE) {
            mmobj_t *shadow_obj1 = shadow_create();
            if(shadow_obj1 == NULL) {
                err = -ENOMEM;
                break;
            }

            mmobj_t *shadow_obj2 = shadow_create();
            if(shadow_obj2 == NULL) {
                err = -ENOMEM;
                break;
            }

            shadow_obj1->mmo_ops->ref(shadow_obj1);
            KASSERT(shadow_obj1->mmo_refcount == 1);
            shadow_obj2->mmo_ops->ref(shadow_obj2);
            KASSERT(shadow_obj2->mmo_refcount == 1);

            setup_shadow_obj(oldvma, shadow_obj1);
            setup_shadow_obj(newvma, shadow_obj2);
        }
        old_cur = old_cur->l_next;
        new_cur = new_cur->l_next;
    }

    if(old_cur == old_vma_list) {
        KASSERT(new_cur == new_vma_list);
    }

    if(err < 0) {
        vmmap_revert(old_vma_list, new_vma_list);
        vmmap_destroy(new_vmmap);
        return err;
    }

    vmmap_destroy(p->p_vmmap);
    p->p_vmmap = new_vmmap;
    return 0;
}
/*
 * The implementation of fork(2). Once this works,
 * you're practically home free. This is what the
 * entirety of Weenix has been leading up to.
 * Go forth and conquer.
 */
int
do_fork(struct regs *regs)
{
        vmarea_t *vma, *clone_vma;
        pframe_t *pf;
        mmobj_t *to_delete, *new_shadowed;

        /* create a new proc*/
        proc_t *child_proc = proc_create("forkedproc");

        if(child_proc == NULL) {
            curthr->kt_errno = ENOMEM;
            return -1;
        }

        /* copy the vmmap to new proc */
        int err = copy_vmmap(child_proc);

        if(err < 0) {
            clean_proc(child_proc);
            curthr->kt_errno = err;
            return -1;
        }


}
