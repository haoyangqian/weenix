#include "errno.h"
#include "globals.h"

#include "proc/kmutex.h"
#include "proc/kthread.h"
#include "proc/proc.h"
#include "proc/sched.h"

#include "test/kshell/kshell.h"
#include "test/kshell/io.h"

#include "util/debug.h"
#include "util/init.h"
#include "util/string.h"

static int check_in_parent_list(proc_t *proc) {
    proc_t* p;
    list_iterate_begin(&proc->p_pproc->p_children, p, proc_t, p_child_link) {
        if (p == proc) {
            return 1;
        }
    } list_iterate_end();
    return 0;
}

static void*
my_tester(int arg1, void *arg2) {
    dbg(DBG_TEST, "Running my_tester method from test thread %d\n", arg1);

    return NULL;
}

static void*
my_tester_do_exit(int arg1, void *arg2) {
    dbg(DBG_TEST, "Running my_tester_do_exit method from test thread %d\n", arg1);
    do_exit(1);
    return NULL;
}

static void*
my_tester_do_waitpid(int arg1, void *arg2) {
    int status;

    dbg(DBG_TEST, "testing do_waitpid on PID -1 \n");
    KASSERT(do_waitpid(-1, 0, &status) == -ECHILD);

    
}

/*
*  Create one process, check its attribute and set up a thread for it.
*
*/
static void test_proc_create() {
    dbg(DBG_TEST, "start testing proc create...\n");
    char* name = "new proc";
    proc_t *proc = proc_create(name);

    KASSERT(proc != NULL && proc->p_pid > 1);
    KASSERT(list_empty(&proc->p_threads));
    KASSERT(list_empty(&proc->p_children));
    /* check the proc has parent, and we are in the parent's children list */
    KASSERT(proc->p_pproc != NULL);
    KASSERT(check_in_parent_list(proc));
    /* check the proc state */
    KASSERT(proc->p_state == PROC_RUNNING);
    /* make sure that this proc is in the proc list */
    KASSERT(proc_lookup(proc->p_pid) == proc);
    /* check the proc name */
    KASSERT(strcmp(proc->p_comm, name) == 0);

    /* set up a thread for proc */
    kthread_t *thr = kthread_create(proc, my_tester, 0 ,NULL);
    sched_make_runnable(thr);

    /* wait this proc to exit */
    int status;
    do_waitpid(proc->p_pid, 0, &status);

    dbg(DBG_TEST, "pass testing proc create!\n");
}


/*
*/
static void test_proc_kill_all() {
    
}


void run_proc_test() {
    test_proc_create();
}