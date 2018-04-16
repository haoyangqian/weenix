#include "kernel.h"
#include "errno.h"
#include "globals.h"

#include "vm/vmmap.h"
#include "vm/shadow.h"
#include "vm/anon.h"

#include "proc/proc.h"

#include "util/debug.h"
#include "util/list.h"
#include "util/string.h"
#include "util/printf.h"

#include "fs/vnode.h"
#include "fs/file.h"
#include "fs/fcntl.h"
#include "fs/vfs_syscall.h"

#include "mm/slab.h"
#include "mm/page.h"
#include "mm/mm.h"
#include "mm/mman.h"
#include "mm/mmobj.h"

static slab_allocator_t *vmmap_allocator;
static slab_allocator_t *vmarea_allocator;

void
vmmap_init(void)
{
        vmmap_allocator = slab_allocator_create("vmmap", sizeof(vmmap_t));
        KASSERT(NULL != vmmap_allocator && "failed to create vmmap allocator!");
        vmarea_allocator = slab_allocator_create("vmarea", sizeof(vmarea_t));
        KASSERT(NULL != vmarea_allocator && "failed to create vmarea allocator!");
}

vmarea_t *
vmarea_alloc(void)
{
        vmarea_t *newvma = (vmarea_t *) slab_obj_alloc(vmarea_allocator);
        if (newvma) {
                newvma->vma_vmmap = NULL;
        }
        return newvma;
}

void
vmarea_free(vmarea_t *vma)
{
        KASSERT(NULL != vma);
        slab_obj_free(vmarea_allocator, vma);
}

/* Create a new vmmap, which has no vmareas and does
 * not refer to a process. */
vmmap_t *
vmmap_create(void)
{
        vmmap_t *newvmm = (vmmap_t *) slab_obj_alloc(vmmap_allocator);

        if(newvmm) {
            list_init(&newvmm->vmm_list);
            newvmm->vmm_proc = NULL;
        }

        return newvmm;
}

/* Removes all vmareas from the address space and frees the
 * vmmap struct. */
void
vmmap_destroy(vmmap_t *map)
{
        vmarea_t *curr;
        list_iterate_begin(&map->vmm_list, curr, vmarea_t, vma_plink){
            if(curr->vma_obj != NULL) {
                curr->vma_obj->mmo_ops->put(curr->vma_obj);
            }

            list_remove(&curr->vma_plink);
            
            if(list_link_is_linked(&curr->vma_olink)) {
                list_remove(&curr->vma_olink);
            }

            vmarea_free(curr);
        }list_iterate_end();

        // free the vmmap
        slab_obj_free(vmmap_allocator, map);
}

/* Add a vmarea to an address space. Assumes (i.e. asserts to some extent)
 * the vmarea is valid.  This involves finding where to put it in the list
 * of VM areas, and adding it. Don't forget to set the vma_vmmap for the
 * area. */
void
vmmap_insert(vmmap_t *map, vmarea_t *newvma)
{   

        KASSERT(map != NULL);
        KASSERT(newvma != NULL);
        KASSERT(newvma->vma_start < newvma->vma_end);
        newvma->vma_vmmap = map;

        /* insert the newvma as sorted */
        list_t *list = &map->vmm_list;
        list_link_t *link = list->l_next;
        for(link = list->l_next; link != list; link = link->l_next){
            vmarea_t *curr = list_item(link, vmarea_t, vma_plink);

            if(curr->vma_start >= newvma->vma_start) {
                /* make sure no overlap */
                KASSERT(newvma->vma_end <= curr->vma_start);
                list_insert_before(link, &newvma->vma_plink);
                return;
            }
        }

        /* if we got here, entail the newvma */
        list_insert_tail(list, &newvma->vma_plink);
}

/*   Check if we can directly find a contiguous range in vmm boundary.
 *   If so, no need to iterate vmarea list.
 */
int 
check_boundary(vmmap_t *map, uint32_t npages, int dir) {
    KASSERT(map != NULL);
    KASSERT(dir == VMMAP_DIR_LOHI || dir == VMMAP_DIR_HILO);

    if(dir == VMMAP_DIR_HILO) {
        if(list_empty(&map->vmm_list)) {
            return MAX_PAGENUM - npages;
        }

        list_t *list = &map->vmm_list;
        list_link_t *link = list->l_prev;

        vmarea_t *curr = list_item(link, vmarea_t, vma_plink);

        if(MAX_PAGENUM - curr->vma_end >= npages) {
            return MAX_PAGENUM - npages;
        }

    } else {
        if(list_empty(&map->vmm_list)) {
            return MIN_PAGENUM;
        }

        list_t *list = &map->vmm_list;
        list_link_t *link = list->l_next;

        vmarea_t *curr = list_item(link, vmarea_t, vma_plink);

        if(curr->vma_start - MIN_PAGENUM >= npages) {
            return MIN_PAGENUM;
        }
    }

    return -1;
}


/* Find a contiguous range of free virtual pages of length npages in
 * the given address space. Returns starting vfn for the range,
 * without altering the map. Returns -1 if no such range exists.
 *
 * Your algorithm should be first fit. If dir is VMMAP_DIR_HILO, you
 * should find a gap as high in the address space as possible; if dir
 * is VMMAP_DIR_LOHI, the gap should be as low as possible. */
int
vmmap_find_range(vmmap_t *map, uint32_t npages, int dir)
{
    KASSERT(map != NULL);
    KASSERT(dir == VMMAP_DIR_LOHI || dir == VMMAP_DIR_HILO);

    if(npages > TOTAL_RANGE) {
        dbg(DBG_VM, "npages should not be larger than TOTAL_RANGE.\n");
        return -1;
    }

    /* check the boundary*/
    int check_ret = check_boundary(map, npages, dir);
    if(check_ret != -1) {
        return check_ret;
    }

    /* no contiguous space near boundary, so iterate the vmarea list. */
    if(dir == VMMAP_DIR_HILO) {
        list_t *list = &map->vmm_list;
        list_link_t *link = list->l_prev;

        vmarea_t *prev = NULL;

        for(link = list->l_next; link != list; link = link->l_prev) {
            vmarea_t *curr = list_item(link, vmarea_t, vma_plink);

            if(prev != NULL && (prev->vma_start - curr->vma_end) >= npages) {
                return prev->vma_start - npages;
            }

            prev = curr;
        }

    } else {
        list_t *list = &map->vmm_list;
        list_link_t *link = list->l_next;

        vmarea_t *prev = NULL;

        for(link = list->l_next; link != list; link = link->l_next){
            vmarea_t *curr = list_item(link, vmarea_t, vma_plink);

            if(prev != NULL && (curr->vma_start - prev->vma_end) >= npages) {
                return prev->vma_end;
            }

            prev = curr;
        }
    }

    /* no such contiguous space was found. */
    return -1;
}

/* Find the vm_area that vfn lies in. Simply scan the address space
 * looking for a vma whose range covers vfn. If the page is unmapped,
 * return NULL. */
vmarea_t *
vmmap_lookup(vmmap_t *map, uint32_t vfn)
{
    KASSERT(map != NULL);

    if(vfn < MIN_PAGENUM || vfn >= MAX_PAGENUM) return NULL;

    list_t *list = &map->vmm_list;
    list_link_t *link = list->l_next;

    for(link = list->l_next; link != list; link = link->l_next){
        vmarea_t *curr = list_item(link, vmarea_t, vma_plink);

        if(vfn >= curr->vma_start && vfn < curr->vma_end) {
            return curr;
        }
    }

    return NULL;
}

/* Allocates a new vmmap containing a new vmarea for each area in the
 * given map. The areas should have no mmobjs set yet. Returns pointer
 * to the new vmmap on success, NULL on failure. This function is
 * called when implementing fork(2). */
vmmap_t *
vmmap_clone(vmmap_t *map)
{
    /* create a new map */
    vmmap_t *newmap = vmmap_create();

    if(newmap == NULL) return NULL;

    vmarea_t *curr;
    list_iterate_begin(&map->vmm_list, curr, vmarea_t, vma_plink){
        vmarea_t *new_vmarea = vmarea_alloc();

        if(new_vmarea == NULL) {
            vmmap_destroy(newmap);
            return NULL;
        }

        new_vmarea->vma_start = curr->vma_start;
        new_vmarea->vma_end   = curr->vma_end;
        new_vmarea->vma_off   = curr->vma_off;

        new_vmarea->vma_prot  = curr->vma_prot;
        new_vmarea->vma_flags = curr->vma_flags;

        new_vmarea->vma_vmmap = newmap;
        new_vmarea->vma_obj   = NULL;
        list_link_init(&new_vmarea->vma_plink);
        list_link_init(&new_vmarea->vma_olink);

        list_insert_tail(&newmap->vmm_list, &new_vmarea->vma_plink);
    }list_iterate_end();

    return newmap; 
}

/* Insert a mapping into the map starting at lopage for npages pages.
 * If lopage is zero, we will find a range of virtual addresses in the
 * process that is big enough, by using vmmap_find_range with the same
 * dir argument.  If lopage is non-zero and the specified region
 * contains another mapping that mapping should be unmapped.
 *
 * If file is NULL an anon mmobj will be used to create a mapping
 * of 0's.  If file is non-null that vnode's file will be mapped in
 * for the given range.  Use the vnode's mmap operation to get the
 * mmobj for the file; do not assume it is file->vn_obj. Make sure all
 * of the area's fields except for vma_obj have been set before
 * calling mmap.
 *
 * If MAP_PRIVATE is specified set up a shadow object for the mmobj.
 *
 * All of the input to this function should be valid (KASSERT!).
 * See mmap(2) for for description of legal input.
 * Note that off should be page aligned.
 *
 * Be very careful about the order operations are performed in here. Some
 * operation are impossible to undo and should be saved until there
 * is no chance of failure.
 *
 * If 'new' is non-NULL a pointer to the new vmarea_t should be stored in it.
 */
int
vmmap_map(vmmap_t *map, vnode_t *file, uint32_t lopage, uint32_t npages,
          int prot, int flags, off_t off, int dir, vmarea_t **new)
{
        /* make sure all the input is valid */
        KASSERT(map != NULL);
        KASSERT(prot == PROT_NONE || prot == PROT_READ || prot == PROT_WRITE
                || prot == PROT_EXEC || prot == (PROT_READ | PROT_WRITE)
                || prot == (PROT_READ | PROT_EXEC)
                || prot == (PROT_WRITE | PROT_EXEC)
                || prot == (PROT_READ | PROT_WRITE | PROT_EXEC));

        KASSERT((flags & MAP_TYPE) == MAP_SHARED || (flags & MAP_TYPE) == MAP_PRIVATE);
        KASSERT(off % PAGE_SIZE == 0);

        if(lopage == 0) {
            KASSERT(dir == VMMAP_DIR_LOHI || dir == VMMAP_DIR_HILO);
        }

        vmarea_t *new_vma = vmarea_alloc();

        if(new_vma == NULL) {
            return -ENOMEM;
        }

        /* determine the start pagenum*/
        int start_page = lopage;
        if(lopage == 0) {
            start_page = vmmap_find_range(map, npages, dir);
            if(start_page < 0) {
                vmarea_free(new_vma);
                return -ENOMEM;
            }
        }

        /* init the attributes of new_vma */
        new_vma->vma_start = start_page;
        new_vma->vma_end   = start_page + npages;
        new_vma->vma_off   = ADDR_TO_PN(off);
        new_vma->vma_prot  = prot;
        new_vma->vma_flags = flags;
        list_link_init(&new_vma->vma_plink);
        list_link_init(&new_vma->vma_olink);

        /* unmap the original mapping*/
        int remove_res = vmmap_remove(map, start_page, npages);
        if(remove_res < 0){
            vmarea_free(new_vma);
            return remove_res;
        }

        /* get the new mmobj */
        mmobj_t *new_mmobj;
        if(file != NULL) {
            int mmap_res = file->vn_ops->mmap(file, vma, &new_mmobj);

            if(mmap_res < 0) {
                vmarea_free(vma);
                return mmap_res;
            }

        } else {
            new_mmobj = anon_create();
            if(new_mmobj == NULL) {
                vmarea_free(vma);
                return -ENOMEM;
            }
        }

        /* check the flag */
        if(flags & MAP_PRIVATE) {
            mmobj_t *shadow_obj = shadow_create();

            if(shadow_obj == NULL) {
                vmarea_free(vma);
                return -ENOMEM;
            }

            shadow_obj->mmo_shadowed = new_mmobj;
            new_mmobj->mmo_ops->ref(new_mmobj);
        }
}

/*
 * We have no guarantee that the region of the address space being
 * unmapped will play nicely with our list of vmareas.
 *
 * You must iterate over each vmarea that is partially or wholly covered
 * by the address range [addr ... addr+len). The vm-area will fall into one
 * of four cases, as illustrated below:
 *
 * key:
 *          [             ]   Existing VM Area
 *        *******             Region to be unmapped
 *
 * Case 1:  [   ******    ]
 * The region to be unmapped lies completely inside the vmarea. We need to
 * split the old vmarea into two vmareas. be sure to increment the
 * reference count to the file associated with the vmarea.
 *
 * Case 2:  [      *******]**
 * The region overlaps the end of the vmarea. Just shorten the length of
 * the mapping.
 *
 * Case 3: *[*****        ]
 * The region overlaps the beginning of the vmarea. Move the beginning of
 * the mapping (remember to update vma_off), and shorten its length.
 *
 * Case 4: *[*************]**
 * The region completely contains the vmarea. Remove the vmarea from the
 * list.
 */
int
vmmap_remove(vmmap_t *map, uint32_t lopage, uint32_t npages)
{
        NOT_YET_IMPLEMENTED("VM: vmmap_remove");
        return -1;
}

/*
 * Returns 1 if the given address space has no mappings for the
 * given range, 0 otherwise.
 */
int
vmmap_is_range_empty(vmmap_t *map, uint32_t startvfn, uint32_t npages)
{
        NOT_YET_IMPLEMENTED("VM: vmmap_is_range_empty");
        return 0;
}

/* Read into 'buf' from the virtual address space of 'map' starting at
 * 'vaddr' for size 'count'. To do so, you will want to find the vmareas
 * to read from, then find the pframes within those vmareas corresponding
 * to the virtual addresses you want to read, and then read from the
 * physical memory that pframe points to. You should not check permissions
 * of the areas. Assume (KASSERT) that all the areas you are accessing exist.
 * Returns 0 on success, -errno on error.
 */
int
vmmap_read(vmmap_t *map, const void *vaddr, void *buf, size_t count)
{
        NOT_YET_IMPLEMENTED("VM: vmmap_read");
        return 0;
}

/* Write from 'buf' into the virtual address space of 'map' starting at
 * 'vaddr' for size 'count'. To do this, you will need to find the correct
 * vmareas to write into, then find the correct pframes within those vmareas,
 * and finally write into the physical addresses that those pframes correspond
 * to. You should not check permissions of the areas you use. Assume (KASSERT)
 * that all the areas you are accessing exist. Remember to dirty pages!
 * Returns 0 on success, -errno on error.
 */
int
vmmap_write(vmmap_t *map, void *vaddr, const void *buf, size_t count)
{
        NOT_YET_IMPLEMENTED("VM: vmmap_write");
        return 0;
}

/* a debugging routine: dumps the mappings of the given address space. */
size_t
vmmap_mapping_info(const void *vmmap, char *buf, size_t osize)
{
        KASSERT(0 < osize);
        KASSERT(NULL != buf);
        KASSERT(NULL != vmmap);

        vmmap_t *map = (vmmap_t *)vmmap;
        vmarea_t *vma;
        ssize_t size = (ssize_t)osize;

        int len = snprintf(buf, size, "%21s %5s %7s %8s %10s %12s\n",
                           "VADDR RANGE", "PROT", "FLAGS", "MMOBJ", "OFFSET",
                           "VFN RANGE");

        list_iterate_begin(&map->vmm_list, vma, vmarea_t, vma_plink) {
                size -= len;
                buf += len;
                if (0 >= size) {
                        goto end;
                }

                len = snprintf(buf, size,
                               "%#.8x-%#.8x  %c%c%c  %7s 0x%p %#.5x %#.5x-%#.5x\n",
                               vma->vma_start << PAGE_SHIFT,
                               vma->vma_end << PAGE_SHIFT,
                               (vma->vma_prot & PROT_READ ? 'r' : '-'),
                               (vma->vma_prot & PROT_WRITE ? 'w' : '-'),
                               (vma->vma_prot & PROT_EXEC ? 'x' : '-'),
                               (vma->vma_flags & MAP_SHARED ? " SHARED" : "PRIVATE"),
                               vma->vma_obj, vma->vma_off, vma->vma_start, vma->vma_end);
        } list_iterate_end();

end:
        if (size <= 0) {
                size = osize;
                buf[osize - 1] = '\0';
        }
        /*
        KASSERT(0 <= size);
        if (0 == size) {
                size++;
                buf--;
                buf[0] = '\0';
        }
        */
        return osize - size;
}
