#include "kernel.h"
#include "errno.h"

#include "vm/vmmap.h"

#include "mm/slab.h"
#include "mm/page.h"
#include "mm/mm.h"
#include "mm/mman.h"
#include "mm/mmobj.h"
#include "mm/tlb.h"

#include "test/kshell/kshell.h"
#include "test/kshell/io.h"

#include "util/debug.h"
#include "util/init.h"
#include "util/string.h"

#include "test/vmtest/vmmap_unittest.h"

static vmarea_t* 
init_vmarea(uint32_t start, uint32_t end, uint32_t off) {
    vmarea_t *vma = vmarea_alloc();

    vma->vma_start = start;
    vma->vma_end = end;
    vma->vma_off = off;

    vma->vma_prot = PROT_NONE;
    vma->vma_flags = MAP_SHARED;
    vma->vma_vmmap = NULL;
    vma->vma_obj   = NULL;
    list_init(&vma->vma_plink);
    list_init(&vma->vma_olink);

    return vma;
}


static void
vmmap_insert_test() {
    vmmap_t *vmmap = vmmap_create();
    KASSERT(vmmap != NULL && "create vmmap fail.\n");

    vmarea_t* vma1 = init_vmarea(MIN_PAGENUM, MIN_PAGENUM + 1, 0);

    vmmap_insert(vmmap, vma1);

    char buf[1024];

    vmmap_mapping_info(vmmap, buf, 1024);

    dbg(DBG_TESTPASS, "%s\n", buf);

}


void run_vmmap_unit_test(){
    vmmap_insert_test();
}