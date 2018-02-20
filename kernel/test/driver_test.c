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

/******************************************************************************/

/* tty test */
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
    for(i = 0;i < TIMES*4;++i) {
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

/***********************************************************************************/
/*  memdev test */

void test_null_dev() {
    dbg(DBG_TEST, "testing dev null\n");

    char buf[1000];
    bytedev_t *dn = bytedev_lookup(MEM_NULL_DEVID);
    
    KASSERT(dn->cd_ops->read(dn, 0, buf, 500) == 0);
    KASSERT(dn->cd_ops->write(dn, 0, buf, 800 == 800));

    dbg(DBG_TESTPASS, "all dev null tests passed\n");
}

void test_zero_dev() {
    dbg(DBG_TEST, "testing dev zero\n");

    char buf[1000];

    int i;
    for (i = 0; i < 1000; i++){
        buf[i] = 'a';
    }
    bytedev_t *dz = bytedev_lookup(MEM_ZERO_DEVID);

    KASSERT(dz->cd_ops->read(dz, 0, buf, 1000) == 1000);

    int j;
    for (j = 0; j < 1000; j++){
        KASSERT(buf[j] == '\0');
    }

    dbg(DBG_TESTPASS, "all dev zero tests passed\n");
}

void run_memdev_test() {
    dbg(DBG_TEST, "testing memdev\n");
    test_null_dev();
    test_zero_dev();
    dbg(DBG_TESTPASS, "PASS testing memdev\n");
}

/******************************************************************************/

/* ata test*/
typedef struct rw_args{
    blockdev_t *bd;
    char *data;
    int blocknum;
    int num_blocks;
} rw_args_t;

static void *write_func(int arg1, void *arg2) {
    rw_args_t *args = (rw_args_t*) arg2;

    dbg(DBG_TEST, "writing data to block %d\n", args->blocknum);

    char *write_buffer = args->data;
    blockdev_t *bd = args->bd;
    int write_result = bd->bd_ops->write_block(bd, write_buffer, args->blocknum, args->num_blocks);
    KASSERT(write_result == 0); // 0 on success

    dbg(DBG_TESTPASS, "successfully wrote data to block %d\n", args->blocknum);
    return NULL;
}

static void *read_func(int arg1, void *arg2) {
    rw_args_t *args = (rw_args_t*) arg2;

    dbg(DBG_TEST, "reading data to block %d\n", args->blocknum);

    char *read_buffer = args->data;
    blockdev_t *bd = args->bd;
    int read_result = bd->bd_ops->read_block(bd, read_buffer, args->blocknum, args->num_blocks);
    KASSERT(read_result == 0);

    dbg(DBG_TESTPASS, "successfully read data from block %d\n", args->blocknum);
    return NULL;
}

void test_single_readwrite() {
    dbg(DBG_TEST, "testing single reading and writing to disk\n");
    blockdev_t *bd = blockdev_lookup(MKDEVID(1,0));
    KASSERT(bd != NULL);

    char *readbuffer = (char*) page_alloc();
    char *writebuffer = (char*) page_alloc();
    KASSERT(readbuffer != NULL && writebuffer != NULL);

    unsigned int i;
    for(i = 0;i < BLOCK_SIZE;++i) {
        writebuffer[i] = 'a';
    }

    int block_offset = 30;
    rw_args_t read_args = {bd, readbuffer, block_offset, 1};
    rw_args_t write_args = {bd, writebuffer, block_offset, 1};

    proc_t *write_proc = proc_create("ata_write_proc");
    kthread_t *write_thread = kthread_create(write_proc, write_func, 0, (void *) &write_args);
    sched_make_runnable(write_thread);

    proc_t *read_proc = proc_create("ata_read_proc");
    kthread_t *read_thread = kthread_create(read_proc, read_func, 0, (void *) &read_args);
    sched_make_runnable(read_thread);

    int status;
    do_waitpid(write_proc->p_pid, 0, &status);
    do_waitpid(read_proc->p_pid, 0, &status);

    unsigned int j;
    for (j = 0; j < BLOCK_SIZE; j++){
        KASSERT(readbuffer[j] == 'a');
    }

    page_free((void*) writebuffer);
    page_free((void*) readbuffer);

    dbg(DBG_TESTPASS, "pass testing reading and writing to disk\n");
}

void test_multithread_readwrite(){
    dbg(DBG_TEST, "testing multithread reading and writing to disk\n");
    blockdev_t *bd = blockdev_lookup(MKDEVID(1,0));
    KASSERT(bd != NULL);

    int block_to_read = 2;
    int block_to_write = 2;
    char *readbuffer1 = (char*) page_alloc_n(block_to_read);
    char *readbuffer2 = (char*) page_alloc_n(block_to_read);
    char *writebuffer1 = (char*) page_alloc_n(block_to_write);
    char *writebuffer2 = (char*) page_alloc_n(block_to_write);
    KASSERT(readbuffer1 != NULL && readbuffer2 != NULL 
            && writebuffer1 != NULL && writebuffer2 != NULL);

    unsigned int i;
    for(i = 0;i < BLOCK_SIZE*block_to_write;++i) {
        writebuffer1[i] = 'a';
        writebuffer2[i] = 'b';
    }

    int block_offset = 30;
    rw_args_t write_args1 = {bd, writebuffer1, block_offset, block_to_write};
    rw_args_t write_args2 = {bd, writebuffer2, block_offset + block_to_write, block_to_write};
    rw_args_t read_args1 = {bd, readbuffer1, block_offset, block_to_read};
    rw_args_t read_args2 = {bd, readbuffer2, block_offset + block_to_read, block_to_read};

    /* create write procs and threads */
    proc_t *write_proc1 = proc_create("ata_write_proc");
    kthread_t *write_thread1 = kthread_create(write_proc1, write_func, 0, (void *) &write_args1);
    sched_make_runnable(write_thread1);
    proc_t *write_proc2 = proc_create("ata_write_proc");
    kthread_t *write_thread2 = kthread_create(write_proc2, write_func, 0, (void *) &write_args2);
    sched_make_runnable(write_thread2);

    /* wait these procs to exit */
    int status;
    do_waitpid(write_proc1->p_pid, 0, &status);
    do_waitpid(write_proc2->p_pid, 0, &status);

    /* create read procs and threads */
    proc_t *read_proc1 = proc_create("ata_read_proc");
    kthread_t *read_thread1 = kthread_create(read_proc1, read_func, 0, (void *) &read_args1);
    sched_make_runnable(read_thread1);
    proc_t *read_proc2 = proc_create("ata_read_proc");
    kthread_t *read_thread2 = kthread_create(read_proc2, read_func, 0, (void *) &read_args2);
    sched_make_runnable(read_thread);

    /* wait these procs to exit */
    do_waitpid(read_proc1->p_pid, 0, &status);
    do_waitpid(read_proc2->p_pid, 0, &status);

    unsigned int j;
    for (j = 0; j < BLOCK_SIZE * block_to_read; j++){
        KASSERT(readbuffer1[j] == 'a');
        KASSERT(readbuffer2[j] == 'b');
    }

    page_free_n((void*)readbuffer1, block_to_read);
    page_free_n((void*)readbuffer2, block_to_read);
    page_free_n((void*)writebuffer1, block_to_write);
    page_free_n((void*)writebuffer2, block_to_write);

    dbg(DBG_TESTPASS, "pass testing multithread reading and writing to disk\n");
}


static void *stress_test(){
    dbg(DBG_TEST, "stress testing reading and writing to disk\n");

    /* test read many blocks in a short time */
    char *readbuffer = (char*) page_alloc();
    char *writebuffer = (char*) page_alloc();
    KASSERT(readbuffer != NULL && writebuffer != NULL);

    unsigned int i;
    for(i = 0;i < BLOCK_SIZE;++i) {
        writebuffer[i] = 'a';
    }

    dbg(DBG_TEST, "test read many blocks");
    int j;
    for (j = 0; j < 1024; j++){
        int read_result = bd->bd_ops->read_block(bd, readbuffer, j, 1);
        KASSERT(read_result == 0);
    }

    dbg(DBG_TEST, "test write many blocks");
    for (j = 0; j < 1024; j++){
        int write_result = bd->bd_ops->write_block(bd, writebuffer, j, 1);
        KASSERT(read_result == 0);
    }

    dbg(DBG_TEST, "test read many blocks from the written blocks");
    for (j = 0; j < 1024; j++){
        int read_result = bd->bd_ops->read_block(bd, readbuffer, j, 1);
        KASSERT(read_result == 0);

        for(i = 0;i < BLOCK_SIZE;++i) {
            KASSERT(readbuffer[i] == 'a');
        }
    }

    page_free((void*) writebuffer);
    page_free((void*) readbuffer);

    /* test large block reads and write */
    int k;
    for(k = 1;k <= 128;++k) {
        char *readbuffer = (char*) page_alloc_n(k);
        char *writebuffer = (char*) page_alloc_n(k);
        KASSERT(readbuffer != NULL && writebuffer != NULL);

        unsigned int m;
        for(m = 0;m < BLOCK_SIZE*k;++m) {
            writebuffer[m] = 'a';
        }

        dbg(DBG_TEST, "test write large blocks with %d blocks\n", k);
        int write_result = bd->bd_ops->write_block(bd, writebuffer, 0, k);
        KASSERT(write_result == 0);

        dbg(DBG_TEST, "test read large blocks with %d blocks\n", k);
        int read_result = bd->bd_ops->read_block(bd, readbuffer, 0, k);
        KASSERT(read_result == 0);
        
        for(m = 0;m < BLOCK_SIZE*k;++m) {
            KASSERT(readbuffer[m] == 'a');
        }

        page_free_n((void*) readbuffer, k);
        page_free_n((void*) writebuffer, k);
    }

    dbg(DBG_TESTPASS, "pass stress testing reading and writing to disk\n");
}


void run_ata_test() {
    dbg(DBG_TEST, "testing ata device\n");
    test_single_readwrite();
    test_multithread_readwrite();
    stress_test();
    dbg(DBG_TESTPASS, "PASS testing ata device\n");
}


/******************************************************************************/
void run_driver_test() {
    dbg(DBG_TEST, "testing drivers\n");
    run_tty_test();
    run_memdev_test();

    dbg(DBG_TESTPASS, "PASS testing drivers\n");
}
