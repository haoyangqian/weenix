#include "config.h"
#include "globals.h"

#include "errno.h"

#include "util/init.h"
#include "util/debug.h"
#include "util/list.h"
#include "util/string.h"

#include "proc/kthread.h"
#include "proc/proc.h"
#include "proc/sched.h"

#include "mm/slab.h"
#include "mm/page.h"

kthread_t *curthr; /* global */
static slab_allocator_t *kthread_allocator = NULL;

#ifdef __MTP__
/* Stuff for the reaper daemon, which cleans up dead detached threads */
static proc_t *reapd = NULL;
static kthread_t *reapd_thr = NULL;
static ktqueue_t reapd_waitq;
static list_t kthread_reapd_deadlist; /* Threads to be cleaned */

static void *kthread_reapd_run(int arg1, void *arg2);
#endif

void
kthread_init()
{
        kthread_allocator = slab_allocator_create("kthread", sizeof(kthread_t));
        KASSERT(NULL != kthread_allocator);
}

/**
 * Allocates a new kernel stack.
 *
 * @return a newly allocated stack, or NULL if there is not enough
 * memory available
 */
static char *
alloc_stack(void)
{
        /* extra page for "magic" data */
        char *kstack;
        int npages = 1 + (DEFAULT_STACK_SIZE >> PAGE_SHIFT);
        kstack = (char *)page_alloc_n(npages);

        return kstack;
}

/**
 * Frees a stack allocated with alloc_stack.
 *
 * @param stack the stack to free
 */
static void
free_stack(char *stack)
{
        page_free_n(stack, 1 + (DEFAULT_STACK_SIZE >> PAGE_SHIFT));
}

/*
 * Allocate a new stack with the alloc_stack function. The size of the
 * stack is DEFAULT_STACK_SIZE.
 *
 * Don't forget to initialize the thread context with the
 * context_setup function. The context should have the same pagetable
 * pointer as the process.
 */
kthread_t *
kthread_create(struct proc *p, kthread_func_t func, long arg1, void *arg2)
{
        KASSERT(p != NULL && "the process is NULL!\n");
        
        /* alloc slab for thread */
        kthread_t *thr = slab_obj_alloc(kthread_allocator);
        if(thr == NULL) {
                return NULL;
        }

        /* alloc stack for thread */
        char* stack = alloc_stack();
        if(stack == NULL) {
                slab_obj_free(kthread_allocator, thr);
                return NULL;
        }

        /* set attribute */
        thr->kt_kstack = stack;
        thr->kt_proc = p;
        thr->kt_errno = thr->kt_cancelled = 0;
        thr->kt_wchan = NULL;
        thr->kt_state = KT_NO_STATE;

        /* init list links */
        list_link_init(&thr->kt_qlink);
        list_link_init(&thr->kt_plink);
        list_insert_head(&p->p_threads, &thr->kt_plink);

        /* setup the context */
        context_setup(&thr->kt_ctx, func, arg1, arg2, thr->kt_kstack, DEFAULT_STACK_SIZE, p->p_pagedir);
        return thr;
}

void
kthread_destroy(kthread_t *t)
{
        KASSERT(t && t->kt_kstack);
        free_stack(t->kt_kstack);
        if (list_link_is_linked(&t->kt_plink))
                list_remove(&t->kt_plink);

        slab_obj_free(kthread_allocator, t);
}

/*
 * If the thread to be cancelled is the current thread, this is
 * equivalent to calling kthread_exit. Otherwise, the thread is
 * sleeping (either on a waitqueue or a runqueue) 
 * and we need to set the cancelled and retval fields of the
 * thread. On wakeup, threads should check their cancelled fields and
 * act accordingly. 
 *
 * If the thread's sleep is cancellable, cancelling the thread should
 * wake it up from sleep.
 *
 * If the thread's sleep is not cancellable, we do nothing else here.
 *
 */
void
kthread_cancel(kthread_t *kthr, void *retval)
{
        KASSERT(kthr != NULL);
        if(kthr == curthr) {
                kthread_exit(retval);
        } else {
                kthr->kt_cancelled = 1;
                kthr->kt_retval = retval;

                /* if the sleep is cancellable, wake up the thread */
                if(kthr->kt_state ==  KT_SLEEP_CANCELLABLE) {
                        sched_wakeup_on(kthr->kt_wchan);
                }
        }
}

/*
 * You need to set the thread's retval field and alert the current
 * process that a thread is exiting via proc_thread_exited. You should
 * refrain from setting the thread's state to KT_EXITED until you are
 * sure you won't make any more blocking calls before you invoke the
 * scheduler again.
 *
 * It may seem unneccessary to push the work of cleaning up the thread
 * over to the process. However, if you implement MTP, a thread
 * exiting does not necessarily mean that the process needs to be
 * cleaned up.
 *
 * The void * type of retval is simply convention and does not necessarily
 * indicate that retval is a pointer
 */
void
kthread_exit(void *retval)
{
        curthr->kt_retval = retval;
        curthr->kt_state = KT_EXITED;
        proc_thread_exited(retval);
}

/*
 * The new thread will need its own context and stack. Think carefully
 * about which fields should be copied and which fields should be
 * freshly initialized.
 *
 * You do not need to worry about this until VM.
 */
kthread_t *
kthread_clone(kthread_t *thr)
{
        kthread_t *newthr = slab_obj_alloc(kthread_allocator);

        if(newthr == NULL) return NULL;

        char *stack = alloc_stack();

        if(stack == NULL) {
                slab_obj_free(kthread_allocator, newthr);
                return NULL;
        }

        newthr->kt_kstack = stack;
        newthr->kt_retval = thr->kt_retval;
        newthr->kt_errno  = thr->kt_errno;
        newthr->kt_proc   = NULL;
        newthr->kt_cancelled = thr->kt_cancelled;

        KASSERT(thr->kt_wchan == NULL);
        newthr->kt_wchan  = thr->kt_wchan;

        KASSERT(thr->kt_state == KT_RUN);
        newthr->kt_state = thr->kt_state;

        KASSERT(!list_link_is_linked(&thr->kt_qlink));
        list_link_init(&newthr->kt_qlink);

        list_link_init(&newthr->kt_plink);

        return newthr;
}

/*
 * The following functions will be useful if you choose to implement
 * multiple kernel threads per process. This is strongly discouraged
 * unless your weenix is perfect.
 */
#ifdef __MTP__
int
kthread_detach(kthread_t *kthr)
{
        NOT_YET_IMPLEMENTED("MTP: kthread_detach");
        return 0;
}

int
kthread_join(kthread_t *kthr, void **retval)
{
        NOT_YET_IMPLEMENTED("MTP: kthread_join");
        return 0;
}

/* ------------------------------------------------------------------ */
/* -------------------------- REAPER DAEMON ------------------------- */
/* ------------------------------------------------------------------ */
static __attribute__((unused)) void
kthread_reapd_init()
{
        NOT_YET_IMPLEMENTED("MTP: kthread_reapd_init");
}
init_func(kthread_reapd_init);
init_depends(sched_init);

void
kthread_reapd_shutdown()
{
        NOT_YET_IMPLEMENTED("MTP: kthread_reapd_shutdown");
}

static void *
kthread_reapd_run(int arg1, void *arg2)
{
        NOT_YET_IMPLEMENTED("MTP: kthread_reapd_run");
        return (void *) 0;
}
#endif
