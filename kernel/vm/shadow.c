#include "globals.h"
#include "errno.h"

#include "util/string.h"
#include "util/debug.h"

#include "mm/mmobj.h"
#include "mm/pframe.h"
#include "mm/mm.h"
#include "mm/page.h"
#include "mm/slab.h"
#include "mm/tlb.h"

#include "vm/vmmap.h"
#include "vm/shadow.h"
#include "vm/shadowd.h"

#define SHADOW_SINGLETON_THRESHOLD 5

int shadow_count = 0; /* for debugging/verification purposes */
#ifdef __SHADOWD__
/*
 * number of shadow objects with a single parent, that is another shadow
 * object in the shadow objects tree(singletons)
 */
static int shadow_singleton_count = 0;
#endif

static slab_allocator_t *shadow_allocator;

static void shadow_ref(mmobj_t *o);
static void shadow_put(mmobj_t *o);
static int  shadow_lookuppage(mmobj_t *o, uint32_t pagenum, int forwrite, pframe_t **pf);
static int  shadow_fillpage(mmobj_t *o, pframe_t *pf);
static int  shadow_dirtypage(mmobj_t *o, pframe_t *pf);
static int  shadow_cleanpage(mmobj_t *o, pframe_t *pf);

static mmobj_ops_t shadow_mmobj_ops = {
        .ref = shadow_ref,
        .put = shadow_put,
        .lookuppage = shadow_lookuppage,
        .fillpage  = shadow_fillpage,
        .dirtypage = shadow_dirtypage,
        .cleanpage = shadow_cleanpage
};

/*
 * This function is called at boot time to initialize the
 * shadow page sub system. Currently it only initializes the
 * shadow_allocator object.
 */
void
shadow_init()
{
        shadow_allocator = slab_allocator_create("shadow", sizeof(mmobj_t));
        KASSERT(shadow_allocator != NULL && "failed to create shadow allocator!");
}

/*
 * You'll want to use the shadow_allocator to allocate the mmobj to
 * return, then then initialize it. Take a look in mm/mmobj.h for
 * macros or functions which can be of use here. Make sure your initial
 * reference count is correct.
 */
mmobj_t *
shadow_create()
{       
        // static uint32_t ncreated = 0;

        // if (ncreated++ % 10 == 0){
        //         shadowd_wakeup();
        // }

        mmobj_t *shadow = (mmobj_t*) slab_obj_alloc(shadow_allocator);
        
        if(shadow != NULL) {
                mmobj_init(shadow, &shadow_mmobj_ops);
        }
        return shadow;
}

/* Implementation of mmobj entry points: */

/*
 * Increment the reference count on the object.
 */
static void
shadow_ref(mmobj_t *o)
{
        KASSERT(o->mmo_ops == &shadow_mmobj_ops);
        o->mmo_refcount++;
}

/*
 * Decrement the reference count on the object. If, however, the
 * reference count on the object reaches the number of resident
 * pages of the object, we can conclude that the object is no
 * longer in use and, since it is a shadow object, it will never
 * be used again. You should unpin and uncache all of the object's
 * pages and then free the object itself.
 */
static void
shadow_put(mmobj_t *o)
{
        KASSERT(o->mmo_ops == &shadow_mmobj_ops);
        KASSERT(o->mmo_refcount > o->mmo_nrespages);

        if(--o->mmo_refcount == o->mmo_nrespages) {
                pframe_t *p;
                
                list_iterate_begin(&o->mmo_respages, p, pframe_t, pf_olink){
                        pframe_unpin(p);
                        pframe_free(p);
                } list_iterate_end();  
        }
}

/* This function looks up the given page in this shadow object. The
 * forwrite argument is true if the page is being looked up for
 * writing, false if it is being looked up for reading. This function
 * must handle all do-not-copy-on-not-write magic (i.e. when forwrite
 * is false find the first shadow object in the chain which has the
 * given page resident). copy-on-write magic (necessary when forwrite
 * is true) is handled in shadow_fillpage, not here. It is important to
 * use iteration rather than recursion here as a recursive implementation
 * can overflow the kernel stack when looking down a long shadow chain */
static int
shadow_lookuppage(mmobj_t *o, uint32_t pagenum, int forwrite, pframe_t **pf)
{
        if(forwrite) {
                return pframe_get(o, pagenum, pf);
        }

        pframe_t *p = NULL;
        mmobj_t *curr = o;
        while(p == NULL && curr->mmo_shadowed != NULL){
                p = pframe_get_resident(curr, pagenum);
                curr = curr->mmo_shadowed;
        }

        if(p == NULL) {
                return pframe_lookup(curr, pagenum, 0, pf);
        }

        *pf = p;
        return 0;

}

/* As per the specification in mmobj.h, fill the page frame starting
 * at address pf->pf_addr with the contents of the page identified by
 * pf->pf_obj and pf->pf_pagenum. This function handles all
 * copy-on-write magic (i.e. if there is a shadow object which has
 * data for the pf->pf_pagenum-th page then we should take that data,
 * if no such shadow object exists we need to follow the chain of
 * shadow objects all the way to the bottom object and take the data
 * for the pf->pf_pagenum-th page from the last object in the chain).
 * It is important to use iteration rather than recursion here as a
 * recursive implementation can overflow the kernel stack when
 * looking down a long shadow chain */
static int
shadow_fillpage(mmobj_t *o, pframe_t *pf)
{
        pframe_t *p = NULL;
        mmobj_t *curr = o;

        /* we go down until the bottom object */
        while(p == NULL && curr != o->mmo_un.mmo_bottom_obj) {
                p = pframe_get_resident(curr, pf->pf_pagenum);
                curr = curr->mmo_shadowed;
        }

        if(p == NULL) {
                KASSERT(curr == o->mmo_un.mmo_bottom_obj); // we must get to the bottom
                int look_res = pframe_lookup(curr, pf->pf_pagenum, 1, &p);

                if(look_res < 0) return look_res;
        }

        KASSERT(p != NULL);
        pframe_pin(pf);
        memcpy(pf->pf_addr, p->pf_addr, PAGE_SIZE);

        /* dirty ? */
        return 0;
}

/* These next two functions are not difficult. */

static int
shadow_dirtypage(mmobj_t *o, pframe_t *pf)
{
        return 0;
}

static int
shadow_cleanpage(mmobj_t *o, pframe_t *pf)
{
        return 0;
}
