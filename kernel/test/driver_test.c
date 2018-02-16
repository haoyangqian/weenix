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

    dbg(DBG_TESTPASS, "PASS testing ld read/write\n");
}

void run_tty_test() {
    bytedev_t *bd = bytedev_lookup(MKDEVID(TTY_MAJOR, 0));
    KASSERT(bd != NULL && "No bytedevice found!");

    ld_test(bd);
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