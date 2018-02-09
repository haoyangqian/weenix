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

static int check_in_parent_proc_list(proc_t *proc) {
    proc_t* p;
    list_iterate_begin(&proc->p_pproc->p_children, p, proc_t, p_child_link) {
        if (p == proc) {
            return 1;
        }
    } list_iterate_end();
    return 0;
}

static int check_in_kthread_list(kthread_t *thr) {
    kthread_t *t;
    list_iterate_begin(&thr->kt_proc->p_threads, t, kthread_t, kt_plink) {
        if (t == thr) {
            return 1;
        }
    } list_iterate_end();
    return 0;
}

static void*
my_simple_tester(int arg1, void *arg2) {
    dbg(DBG_TEST, "Running my_tester method from test thread %d\n", arg1);

    return NULL;
}

static void*
my_sleeping_tester(int arg1, void *arg2) {
    dbg(DBG_TEST, "I am going to sleep...\n");
    sched_cancellable_sleep_on((ktqueue_t *) arg2);
    dbg(DBG_TEST, "I am awoken from sleep!\n");

    return NULL;
}

static void*
my_tester_do_waitpid(int arg1, void *arg2) {
    int status;

    dbg(DBG_TEST, "testing do_waitpid on PID -1 \n");
    /* this process has no child */
    KASSERT(do_waitpid(-1, 0, &status) == -ECHILD);

    dbg(DBG_TEST, "testing do_waitpid on specidfic PID  \n");
    /* this process has no child */
    KASSERT(do_waitpid(10, 0, &status) == -ECHILD);

    /* create a child proc*/
    char* name1 = "child proc 1";
    proc_t *child_proc1 = proc_create(name1);
    kthread_t *thr1 = kthread_create(child_proc1, my_simple_tester, 0 ,NULL);
    sched_make_runnable(thr1);

    dbg(DBG_TEST, "testing do_waitpid on PID -1 \n");
    /* this process has one child */
    KASSERT(do_waitpid(-1, 0, &status) == child_proc1->p_pid);

    /* create a child proc*/
    char* name2 = "child proc 2";
    proc_t *child_proc2 = proc_create(name2);
    kthread_t *thr2 = kthread_create(child_proc2, my_simple_tester, 0 ,NULL);
    sched_make_runnable(thr2);

    dbg(DBG_TEST, "testing do_waitpid on specific PID \n");
    /* this process has one child */
    KASSERT(do_waitpid(child_proc2->p_pid, 0, &status) == child_proc2->p_pid);

    return NULL;
}


//static void*
// my_tester_proc_cleanup(int arg1, void *arg2){
//     /* create a child proc*/
//     char* name1 = "child proc 1";
//     proc_t *child_proc1 = proc_create(name1);
//     kthread_t *thr1 = kthread_create(child_proc1, my_sleeping_tester, 0 , (void *)&test_proc->p_wait);
//     sched_make_runnable(thr1);
//     return NULL;
// }

/*
*  Create one process, check its attribute and set up a thread for it.
*
*/
static void test_proc_create() {
    dbg(DBG_TEST, "start testing proc create...\n");
    char* name = "proc 2";
    proc_t *proc = proc_create(name);

    KASSERT(proc != NULL && proc->p_pid > 1);
    KASSERT(list_empty(&proc->p_threads));
    KASSERT(list_empty(&proc->p_children));
    /* check the proc has parent, and we are in the parent's children list */
    KASSERT(proc->p_pproc != NULL);
    KASSERT(check_in_parent_proc_list(proc));
    /* check the proc state */
    KASSERT(proc->p_state == PROC_RUNNING);
    /* make sure that this proc is in the proc list */
    KASSERT(proc_lookup(proc->p_pid) == proc);
    /* check the proc name */
    KASSERT(strcmp(proc->p_comm, name) == 0);

    /* set up a thread for proc */
    kthread_t *thr = kthread_create(proc, my_simple_tester, 0 ,NULL);
    sched_make_runnable(thr);

    /* wait this proc to exit */
    int status;
    do_waitpid(proc->p_pid, 0, &status);

    dbg(DBG_TESTPASS, "pass testing proc create!\n");
}

/*
* Create one process, and create new child process in it, then test do_waitpid.
*/
static void test_proc_do_waitpid() {
    dbg(DBG_TEST, "start testing proc do_waitpid...\n");
    /* create a new process */
    char* name = "proc 3";
    proc_t *proc = proc_create(name);

    /* set up a thread for proc */
    kthread_t *thr = kthread_create(proc, my_tester_do_waitpid, 0 ,NULL);
    sched_make_runnable(thr);

    /* wait this proc to exit */
    int status;
    do_waitpid(proc->p_pid, 0, &status);

    dbg(DBG_TESTPASS, "pass testing proc do_waitpid!\n");
}

/*
*  Create one kthread, check its attribute.
*
*/
static void test_kthread_create() {
    dbg(DBG_TEST, "start testing kthread create...\n");
    /* create a new process */
    char* name = "proc 4";
    proc_t *proc = proc_create(name);
    kthread_t *thr = kthread_create(proc, my_tester_do_waitpid, 0 ,NULL);
    sched_make_runnable(thr);

    /* check attribute */
    KASSERT(thr != NULL);
    KASSERT(thr->kt_kstack != NULL);
    KASSERT(thr->kt_proc == proc);

    KASSERT(thr->kt_cancelled == 0);
    KASSERT(check_in_kthread_list(thr));

    /* wait this proc to exit */
    int status;
    do_waitpid(proc->p_pid, 0, &status);

    dbg(DBG_TESTPASS, "pass testing kthraed create!\n");
}

/*
*  test proc exit and thread exit.
*/
static void test_kthread_cancel(){
    dbg(DBG_TEST, "testing kthread_cancel...");

    /* create a new process */
    char* name = "proc 5";
    proc_t *proc = proc_create(name);
    kthread_t *thr = kthread_create(proc, my_sleeping_tester, 0 ,(void *)&proc->p_wait);
    sched_make_runnable(thr);

    yield();

    kthread_cancel(thr, (void *) 666);

    KASSERT(thr->kt_cancelled == 1);
    KASSERT((int) thr->kt_retval == 666);

    int status;
    do_waitpid(proc->p_pid, 0, &status);

    dbg(DBG_TESTPASS, "pass testing kthraed cancel!\n");
}


/*
*/
static void test_proc_kill() {
    
}

/*
*/
static void test_proc_kill_all() {
    
}


void run_proc_test() {
    test_proc_create();

    test_kthread_create();

    test_proc_do_waitpid();

    test_kthread_cancel();

    dbg(DBG_TESTPASS, "pass all proc and kthread tests!\n");
}