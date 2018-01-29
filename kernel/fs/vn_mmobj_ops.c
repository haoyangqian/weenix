#include "errno.h"
#include "fs/vnode.h"
#include "util/debug.h"
/*
 * Related to implementation of vnode vm_object entry points:
 */

#define mmobj_to_vnode(o) \
        (CONTAINER_OF((o), vnode_t, vn_mmobj))

void
vo_vref(mmobj_t *o)
{
        KASSERT(o);
        vref(mmobj_to_vnode(o));
}

void
vo_vput(mmobj_t *o)
{
        KASSERT(o);
        vput(mmobj_to_vnode(o));
}

int
vlookuppage(mmobj_t *o, uint32_t pagenum, int forwrite, pframe_t **pf)
{
        KASSERT(NULL != pf);
        KASSERT(NULL != o);

        if ((uint32_t) mmobj_to_vnode(o)->vn_len <= pagenum * PAGE_SIZE) {
                return -EINVAL;
        }

        return pframe_get(o, pagenum, pf);
}

int
vreadpage(mmobj_t *o, pframe_t *pf)
{
        KASSERT(NULL != pf);
        KASSERT(NULL != o);

        vnode_t *v = mmobj_to_vnode(o);
        return v->vn_ops->fillpage(v, (int)PN_TO_ADDR(pf->pf_pagenum), pf->pf_addr);
}

int
vdirtypage(mmobj_t *o, pframe_t *pf)
{
        KASSERT(NULL != pf);
        KASSERT(NULL != o);

        vnode_t *v = mmobj_to_vnode(o);
        if (!pframe_is_dirty(pf)) {
                return v->vn_ops->dirtypage(v, (int) PN_TO_ADDR(pf->pf_pagenum));
        } else {
                return 0;
        }
}

int
vcleanpage(mmobj_t *o, pframe_t *pf)
{
        KASSERT(NULL != pf);
        KASSERT(NULL != o);

        vnode_t *v = mmobj_to_vnode(o);
        return v->vn_ops->cleanpage(v, (int) PN_TO_ADDR(pf->pf_pagenum), pf->pf_addr);
}