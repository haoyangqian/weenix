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

static void assert_vma_state(vmarea_t *oldvma, vmarea_t *clonevma, vmmap_t *newvmm){
    KASSERT(oldvma->vma_start == clonevma->vma_start);
    KASSERT(oldvma->vma_end == clonevma->vma_end);
    KASSERT(oldvma->vma_off == clonevma->vma_off);
    KASSERT(oldvma->vma_prot == clonevma->vma_prot);
    KASSERT(oldvma->vma_flags == clonevma->vma_flags);
    KASSERT(oldvma->vma_vmmap == curproc->p_vmmap && clonevma->vma_vmmap == newvmm);
    KASSERT(oldvma->vma_obj != NULL && clonevma->vma_obj == NULL);
    KASSERT(list_link_is_linked(&oldvma->vma_plink));
    KASSERT(list_link_is_linked(&clonevma->vma_plink));
    KASSERT(!list_link_is_linked(&clonevma->vma_olink));
}


static void assert_new_thread_state(kthread_t *k){
    KASSERT(&k->kt_ctx != &curthr->kt_ctx);
    KASSERT(k->kt_kstack != curthr->kt_kstack);
    KASSERT(k->kt_retval == curthr->kt_retval);
    KASSERT(k->kt_errno == curthr->kt_errno);
    KASSERT(k->kt_proc == NULL);
    KASSERT(k->kt_cancelled == curthr->kt_cancelled);
    KASSERT(k->kt_wchan == curthr->kt_wchan);
    KASSERT(k->kt_state == curthr->kt_state);
    KASSERT(list_link_is_linked(&k->kt_qlink)
            == list_link_is_linked(&curthr->kt_qlink));
    KASSERT(!list_link_is_linked(&k->kt_plink));
}

/* set up a shadow object for a specific vmarea. */
static void 
setup_shadow_obj(vmarea_t *vma, mmobj_t *shadow_obj){
    /* get the bottom obj of this vmarea */
    mmobj_t *bottom_obj = mmobj_bottom_obj(vma->vma_obj);

    KASSERT(bottom_obj->mmo_shadowed == NULL);

    /* set the shadow obj and increment the refcount */
    shadow_obj->mmo_un.mmo_bottom_obj = bottom_obj;
    bottom_obj->mmo_ops->ref(bottom_obj);

    shadow_obj->mmo_shadowed = vma->vma_obj;

    if (list_link_is_linked(&vma->vma_olink)){
        list_remove(&vma->vma_olink);
    }

    /* add vma to the list of bottom obj */
    list_insert_tail(&bottom_obj->mmo_un.mmo_vmas, &vma->vma_olink);

    vma->vma_obj = shadow_obj;
}


static void
vmmap_revert(list_t *old_vma_list, list_t *clone_vma_list) {
    list_link_t *old_cur = old_vma_list->l_next;
    list_link_t *clone_cur = clone_vma_list->l_next;

    while(old_cur != old_vma_list) {
        vmarea_t *oldvma = list_item(old_cur, vmarea_t, vma_plink);
        vmarea_t *clonevma = list_item(clone_cur, vmarea_t, vma_plink);

        if(clonevma->vma_obj == NULL) return;

        if((oldvma->vma_flags & MAP_TYPE) == MAP_PRIVATE) {
            KASSERT((clonevma->vma_flags & MAP_TYPE) == MAP_PRIVATE);
            KASSERT(clonevma->vma_obj->mmo_shadowed != NULL);
            KASSERT(oldvma->vma_obj->mmo_shadowed != NULL);

            mmobj_t *old_mmobj = oldvma->vma_obj->mmo_shadowed;
            old_mmobj->mmo_ops->ref(old_mmobj);

            oldvma->vma_obj->mmo_ops->put(oldvma->vma_obj);
            oldvma->vma_obj = old_mmobj;
        }

        old_cur = old_vma_list->l_next;
        clone_cur = clone_vma_list->l_next;
    }

    KASSERT(clone_cur == clone_vma_list);
}

static int
copy_vmmap(proc_t *p) {
    vmmap_t *clone_vmmap = vmmap_clone(curproc->p_vmmap);

    if(clone_vmmap == NULL) {
        return -ENOMEM;
    }

    clone_vmmap->vmm_proc = p;

    list_t *old_vma_list = &curproc->p_vmmap->vmm_list;
    list_t *clone_vma_list = &p->p_vmmap->vmm_list;

    list_link_t *old_cur = old_vma_list->l_next;
    list_link_t *clone_cur = clone_vma_list->l_next;

    int err = 0;
    while(old_cur != old_vma_list && err == 0) {
        vmarea_t *oldvma = list_item(old_cur, vmarea_t, vma_plink);
        vmarea_t *clonevma = list_item(clone_cur, vmarea_t, vma_plink);

        /* make sure the state is correct */
        assert_vma_state(oldvma, clonevma, clone_vmmap);

        /* set up vmobj and increment refcount */
        clonevma->vma_obj = oldvma->vma_obj;
        clonevma->vma_obj->mmo_ops->ref(clonevma->vma_obj);

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

            /* increment the refcount of shadow object */
            shadow_obj1->mmo_ops->ref(shadow_obj1);
            KASSERT(shadow_obj1->mmo_refcount == 1);
            shadow_obj2->mmo_ops->ref(shadow_obj2);
            KASSERT(shadow_obj2->mmo_refcount == 1);

            /* set up shadow object */
            setup_shadow_obj(oldvma, shadow_obj1);
            setup_shadow_obj(clonevma, shadow_obj2);
        }

        old_cur = old_cur->l_next;
        clone_cur = clone_cur->l_next;
    }

    if(old_cur == old_vma_list) {
        KASSERT(clone_cur == clone_vma_list && "the list has different length. ");
    }

    if(err < 0) {
        /* revert the changes if we encounter some errors */
        vmmap_revert(old_vma_list, clone_vma_list);
        vmmap_destroy(clone_vmmap);
        return err;
    }

    vmmap_destroy(p->p_vmmap);
    p->p_vmmap = clone_vmmap;

    return 0;
}

/* clean up the resources of a process */
static void
cleanup_proc(proc_t *p) {
    list_remove(&p->p_list_link);
    list_remove(&p->p_child_link);
    pt_destroy_pagedir(p->p_pagedir);
    vput(p->p_cwd);
    vmmap_destroy(p->p_vmmap);
}


static kthread_t*
create_thread(proc_t *p, struct regs *regs){
    kthread_t *newthr = kthread_clone(curthr);
    if(newthr == NULL) return NULL;

    /* make sure the thread state is correct */
    assert_new_thread_state(newthr);
    
    newthr->kt_proc = p;
    list_insert_tail(&p->p_threads, &newthr->kt_plink);

    regs->r_eax = 0;

    /* setup the stack for new thread */
    uint32_t esp = fork_setup_stack(regs, newthr->kt_kstack);
    
    /* set up new context for new thread */
    newthr->kt_ctx.c_pdptr  = p->p_pagedir;
    newthr->kt_ctx.c_eip    = (uint32_t) userland_entry;
    newthr->kt_ctx.c_esp    = esp;
    newthr->kt_ctx.c_kstack = (uintptr_t) newthr->kt_kstack;
    newthr->kt_ctx.c_kstacksz = DEFAULT_STACK_SIZE;

    return newthr;
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
        /*
        vmarea_t *vma, *clone_vma;
        pframe_t *pf;
        mmobj_t *to_delete, *new_shadowed;*/

        /* create a new proc*/
        proc_t *child_proc = proc_create("forkedproc");

        if(child_proc == NULL) {
            curthr->kt_errno = ENOMEM;
            return -1;
        }

        /* copy the vmmap to new proc */
        int err = copy_vmmap(child_proc);

        if(err < 0) {
            cleanup_proc(child_proc);
            curthr->kt_errno = err;
            return -1;
        }

        /* create a new thread and setup the context */
        kthread_t *newthr = create_thread(child_proc, regs);

        if(newthr == NULL) {
            vmmap_revert(&curproc->p_vmmap->vmm_list, &child_proc->p_vmmap->vmm_list);
            cleanup_proc(child_proc);
            curthr->kt_errno = ENOMEM;
            return -1;
        }


        /* copy file table */
        int i;
        for(i = 0;i < NFILES;++i) {
            KASSERT(child_proc->p_files[i] == NULL);

            child_proc->p_files[i] = curproc->p_files[i];
            if(curproc->p_files[i] != NULL) {
                fref(curproc->p_files[i]);
            }
        }


        /* unmap pagetable and flush TLB, because the parent process might still have 
        * some entries marked as "writable", but we need "copy on write", so we would
        * like access to these pages to cause a trap to page fault handler. */
        tlb_flush_all();
        pt_unmap_range(curproc->p_pagedir, USER_MEM_LOW, USER_MEM_HIGH);

        /* set working directory and brk values */
        child_proc->p_cwd       = curproc->p_cwd;
        if(curproc->p_cwd != NULL) {
            vref(curproc->p_cwd);
        }
        child_proc->p_brk       = curproc->p_brk;
        child_proc->p_start_brk = curproc->p_start_brk;


        /* make the new thread runnable */
        sched_make_runnable(newthr);

        /* set eax to the child's pid */
        regs->r_eax = child_proc->p_pid;

        return child_proc->p_pid;
}
