#include "util/debug.h"

#include "drivers/bytedev.h"
#include "drivers/blockdev.h"
#include "mm/kmalloc.h"
#include "drivers/tty/tty.h"
#include "drivers/tty/n_tty.h"
#include "drivers/memdevs.h"
#include "drivers/disk/ata.h"

#include "proc/proc.h"

#include "test/kshell/kshell.h"
#include "test/kshell/io.h"

#define bd_to_tty(bd) \
        CONTAINER_OF(bd, tty_device_t, tty_cdev) 
#define TIMES 4

static void write_mutilple_chars(bytedev_t *bd, int count, char c) {
    int i;
    for(i = 0;i < count;++i) {
        /* call this function to monitor the key was pressed. */
        tty_global_driver_callback((void *) bd_to_tty(bd), c);
    }
}

/* test for line descipline */
void ld_test(bytedev_t* bd) {
    dbg(DBG_TEST, "testing ld read/write\n");

    char* readbuf = (char*) kmalloc(1000 * sizeof(char));
    KASSERT(readbuf != NULL);

    write_mutilple_chars(bd, 5, 'a');
    write_mutilple_chars(bd, 1, '\n');
    write_mutilple_chars(bd, 10, 'b');
    write_mutilple_chars(bd, 1, '\r');

    /* make sure we're only reading up until newlines(both for \n and \r) */
    int read_chars = 0;
    read_chars = bd->cd_ops->read(bd, 0, readbuf, 1000);
    KASSERT(read_chars == 6);
    read_chars = bd->cd_ops->read(bd, 0, (readbuf+6), 1000);
    KASSERT(read_chars == 11);

    /* make sure the chars in read buf is correct */
    int i;
    for(i = 0;i < 5;++i) {
        KASSERT(readbuf[i] == 'a');
    }
    KASSERT(readbuf[i] == '\n');
    int j;
    for(j = 6;j < 16;++j) {
        KASSERT(readbuf[j] == 'b');
    }
    KASSERT(readbuf[j] == '\r');

    dbg(DBG_TESTPASS, "PASS testing ld read/write\n");
}

static void* read_from_bd1(int c,void *arg2) {
    bytedev_t *bd = (bytedev_t*) arg2;
    char readbuf[30];
    int i;
    for(i = 0;i < TIMES;++i) {
        bd->cd_ops->read(bd, 0, readbuf, 30);

        int j;
        for(j = 0;j < 20;++j) {
            KASSERT(readbuf[j] == c);
        }
        KASSERT(readbuf[j] == '\n');
    }

    return NULL;
}

static void* write_to_bd1(int arg1, void *arg2) {
    bytedev_t *bd = (bytedev_t*) arg2;
    int i;
    for(i = 0;i < TIMES;++i) {
        write_mutilple_chars(bd,20,'a');
        write_mutilple_chars(bd,1,'\n');
        /* yield to other read threads */
        yield(); 
        write_mutilple_chars(bd,20,'b');
        write_mutilple_chars(bd,1,'\n');
        yield();
    }
    return NULL;
}

static void* read_from_bd2(int c,void *arg2) {
    bytedev_t *bd = (bytedev_t*) arg2;
    char readbuf[30];
    int i;
    for(i = 0;i < TIMES*2;++i) {
        bd->cd_ops->read(bd, 0, readbuf, 30);

        int j;
        for(j = 0;j < 20;++j) {
            KASSERT(readbuf[j] == c);
        }
        KASSERT(readbuf[j] == '\n');
    }

    return NULL;
} 

static void* write_to_bd2(int arg1, void *arg2) {
    bytedev_t *bd = (bytedev_t*) arg2;
    int i;
    for(i = 0;i < TIMES;++i) {
        write_mutilple_chars(bd,20,'a');
        write_mutilple_chars(bd,1,'\n');
        yield();
        write_mutilple_chars(bd,20,'a');
        write_mutilple_chars(bd,1,'\n');
        yield();
    }
    return NULL;
}


/* Ensure that we can have two threads simultaneously reading from the same terminal. */
static void test_multiple_threads_read(bytedev_t *bd) {
    dbg(DBG_TEST, "testing multithreaded tty reads and writes\n");

    /* set up two read threads and one read threads */
    proc_t *proc1 = proc_create("multithread_reading_proc_1");
    kthread_t *t1 = kthread_create(proc1, read_from_bd1, 'a', (void*) bd);
    proc_t *proc2 = proc_create("multithread_reading_proc_2");
    kthread_t *t2 = kthread_create(proc2, read_from_bd1, 'b', (void*) bd);

    proc_t *proc3 = proc_create("multithread_writing_proc_1");
    kthread_t *t3 = kthread_create(proc3, write_to_bd1, 0, (void*) bd);
    sched_make_runnable(t1);
    sched_make_runnable(t2);
    sched_make_runnable(t3);

    int status;
    do_waitpid(proc1->p_pid, 0, &status);
    do_waitpid(proc2->p_pid, 0, &status);
    do_waitpid(proc3->p_pid, 0, &status);

    dbg(DBG_TESTPASS, "PASS test_multiple_threads_read\n");
}

/* Ensure that we can have two threads simultaneously writing to the same terminal. */
static void test_multiple_threads_write(bytedev_t *bd) {
    dbg(DBG_TEST, "testing multithreaded tty reads and writes\n");

    /* set up two write threads and one read threads */
    proc_t *proc1 = proc_create("multithread_writing_proc_1");
    kthread_t *t1 = kthread_create(proc1, write_to_bd2, 0, (void*) bd);
    proc_t *proc2 = proc_create("multithread_writing_proc_2");
    kthread_t *t2 = kthread_create(proc2, write_to_bd2, 0, (void*) bd);
    
    proc_t *proc3 = proc_create("multithread_reading_proc_3");
    kthread_t *t3 = kthread_create(proc3, read_from_bd2, 'a', (void*) bd);

    sched_make_runnable(t1);
    sched_make_runnable(t2);
    sched_make_runnable(t3);

    int status;
    do_waitpid(proc1->p_pid, 0, &status);
    do_waitpid(proc2->p_pid, 0, &status);
    do_waitpid(proc3->p_pid, 0, &status);

    dbg(DBG_TESTPASS, "PASS test_multiple_threads_write\n");
}

/* Make sure that, if the internal terminal buffer is full, 
*  Weenix cleanly discards any excess data that comes in.*/
void full_buffer_test(bytedev_t *bd) {
    dbg(DBG_TEST, "testing full buffer\n");
    char readbuf[200];
    /* try to write more than buffer size. */
    write_mutilple_chars(bd, TTY_BUF_SIZE+10,'a');

    int read_chars = bd->cd_ops->read(bd, 0, readbuf, TTY_BUF_SIZE+10);
    KASSERT(read_chars == TTY_BUF_SIZE);
    dbg(DBG_TESTPASS, "PASS testing full buffer\n");
}

/* test tty */
void run_tty_test() {
    dbg(DBG_TEST, "testing tty\n");
    bytedev_t *bd = bytedev_lookup(MKDEVID(TTY_MAJOR, 0));
    KASSERT(bd != NULL && "No bytedevice found!");

    ld_test(bd);
    test_multiple_threads_read(bd);
    test_multiple_threads_write(bd);
    full_buffer_test(bd);
    dbg(DBG_TESTPASS, "PASS testing tty\n");
}

void run_memdev_test() {

}

void run_ata_test() {

}

void run_driver_test() {
    dbg(DBG_TEST, "testing drivers\n");
    run_tty_test();
    dbg(DBG_TESTPASS, "PASS testing drivers\n");
}
