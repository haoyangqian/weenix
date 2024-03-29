#include "drivers/tty/tty.h"

#include "drivers/bytedev.h"

#include "drivers/tty/driver.h"
#include "drivers/tty/keyboard.h"
#include "drivers/tty/ldisc.h"
#include "drivers/tty/n_tty.h"
#include "drivers/tty/screen.h"
#include "drivers/tty/virtterm.h"

#include "mm/kmalloc.h"

#include "util/debug.h"

#define bd_to_tty(bd) \
        CONTAINER_OF(bd, tty_device_t, tty_cdev)

/**
 * The callback function called by the virtual terminal subsystem when
 * a key is pressed.
 *
 * @param arg a pointer to the tty attached to the virtual terminal
 * which received the key press=
 * @param c the character received
 */
/*static void tty_global_driver_callback(void *arg, char c);*/

/**
 * Reads a specified maximum number of bytes from a tty into a given
 * buffer.
 *
 * @param dev the tty to read from
 * @param offset this parameter is ignored in this function
 * @param buf the buffer to read into
 * @param count the maximum number of bytes to read
 * @return the number of bytes read into buf
 */
static int tty_read(bytedev_t *dev, int offset, void *buf, int count);

/**
 * Writes a specified maximum number of bytes from a given buffer into
 * a tty.
 *
 * @param dev the tty to write to
 * @param offset this parameter is ignored in this function
 * @param buf the buffer to read from
 * @param count the maximum number of bytes to write
 * @return the number of bytes written
 */
static int tty_write(bytedev_t *dev, int offset, const void *buf, int count);

/**
 * Echoes out to the tty driver.
 *
 * @param driver the tty driver to echo to
 * @param out the string to echo
 */
static void tty_echo(tty_driver_t *driver, const char *out);

static bytedev_ops_t tty_bytedev_ops = {
        tty_read,
        tty_write,
        NULL,
        NULL,
        NULL,
        NULL
};

void
tty_init()
{
        screen_init();
        vt_init();
        keyboard_init();

        /*
         * Create NTERMS tty's, all with the default line discipline
         * and a virtual terminal driver.
         */
        int nterms, i;

        nterms = vt_num_terminals();
        for (i = 0; i < nterms; ++i) {
                tty_driver_t *ttyd;
                tty_device_t *tty;
                tty_ldisc_t *ldisc;

                ttyd = vt_get_tty_driver(i);
                KASSERT(NULL != ttyd);
                KASSERT(NULL != ttyd->ttd_ops);
                KASSERT(NULL != ttyd->ttd_ops->register_callback_handler);

                tty = tty_create(ttyd, i);
                if (NULL == tty) {
                        panic("Not enough memory to allocate tty\n");
                }

                if (NULL != ttyd->ttd_ops->register_callback_handler(
                            ttyd, tty_global_driver_callback, (void *)tty)) {
                        panic("Callback already registered "
                              "to terminal %d\n", i);
                }

                ldisc = n_tty_create();
                if (NULL == ldisc) {
                        panic("Not enough memory to allocate "
                              "line discipline\n");
                }
                KASSERT(NULL != ldisc);
                KASSERT(NULL != ldisc->ld_ops);
                KASSERT(NULL != ldisc->ld_ops->attach);
                ldisc->ld_ops->attach(ldisc, tty);

                if (bytedev_register(&tty->tty_cdev) != 0) {
                        panic("Error registering tty as byte device\n");
                }
        }
}

/*
 * Initialize a tty device. The driver should not be NULL, but we don't
 * need a line descriptor yet. To initialize the fields of the byte device in
 * the tty struct, use the MKDEVID macro and the correct byte device function
 * table for a tty.
 */
tty_device_t *
tty_create(tty_driver_t *driver, int id)
{
    if(driver == NULL) return NULL;
    tty_device_t *tty = (tty_device_t*) kmalloc(sizeof(tty_device_t));
    if(tty == NULL) return NULL;
    /* set up attributes for driver */
    tty->tty_driver = driver;
    tty->tty_id = id;
    tty->tty_ldisc = NULL;

    tty->tty_cdev.cd_id = MKDEVID(2,id);
    tty->tty_cdev.cd_ops = &tty_bytedev_ops;
    list_link_init(&tty->tty_cdev.cd_link);
    return tty;
}

/*
 * This is the function called by the virtual terminal subsystem when
 * a key is pressed.
 *
 * The first thing you should do is to pass the character to the line
 * discipline. This way, the character will be buffered, so that when
 * the read system call is made, an entire line will be returned,
 * rather than just a single character.
 *
 * After passing the character off to the line discipline, the result
 * of receive_char() should be echoed to the screen using the
 * tty_echo() function.
 */
void
tty_global_driver_callback(void *arg, char c)
{
    tty_device_t *tty = (tty_device_t*) arg;
    KASSERT(tty != NULL && "tty should not be NULL");
    tty_ldisc_t *ldisc = tty->tty_ldisc;
    struct tty_ldisc_ops *ops = ldisc->ld_ops;

    const char *out = ops->receive_char(ldisc, c);
    if(out != NULL) {
        tty_echo(tty->tty_driver, out);
    } else {
        dbg(DBG_TERM, "unable to print to screen\n");
    }
}

/*
 * You should use the driver's provide_char function to output
 * each character of the string 'out'.
 */
void
tty_echo(tty_driver_t *driver, const char *out)
{
    KASSERT(driver != NULL && "tty should not be NULL");
    if(out == NULL) return;
    /* save the address in order to free */
    void *to_free = (void *) out;
    while(*out != '\0') {
        driver->ttd_ops->provide_char(driver, *out);
        out++;
    }
    /* free the memory */
    kfree(to_free);
}

/*
 * In this function, you should block I/O, call the line discipline,
 * and unblock I/O. We do not want to receive interrupts while
 * modifying the input buffer.
 */
int
tty_read(bytedev_t *dev, int offset, void *buf, int count)
{
    KASSERT(dev != NULL);
    KASSERT(buf != NULL);
    tty_ldisc_t *ldisc = bd_to_tty(dev)->tty_ldisc;
    tty_driver_t *driver = bd_to_tty(dev)->tty_driver;

    KASSERT(ldisc != NULL);
    KASSERT(driver != NULL);

    void *data = driver->ttd_ops->block_io(driver);
    int read_bytes = ldisc->ld_ops->read(ldisc, buf, count);
    driver->ttd_ops->unblock_io(driver,data);
    return read_bytes;
}

/*
 * In this function, you should block I/O using the tty driver's block_io
 * function, process each character with the line discipline and output the
 * result to the driver, and then unblock I/O using the tty driver's unblock_io
 * function.
 *
 * Important: You should return the number of bytes processed,
 * _NOT_ the number of bytes written out to the driver. For
 * example, '\n' should be one character instead of two although
 * it becomes '\r\n' after being processed. 
 */
int
tty_write(bytedev_t *dev, int offset, const void *buf, int count)
{
    KASSERT(dev != NULL);
    KASSERT(buf != NULL);
    tty_ldisc_t *ldisc = bd_to_tty(dev)->tty_ldisc;
    tty_driver_t *driver = bd_to_tty(dev)->tty_driver;

    KASSERT(ldisc != NULL);
    KASSERT(driver != NULL);

    const char *buffer = (const char*) buf;
    void *data = driver->ttd_ops->block_io(driver);
    int i;
    for(i = 0;i < count;++i) {
        const char *to_echo = ldisc->ld_ops->process_char(ldisc, buffer[i]);
        if(to_echo != NULL) {
            tty_echo(driver, to_echo);
        } else {
            dbg(DBG_TERM, "unable to print to screen\n");
            break;
        }
    }
    driver->ttd_ops->unblock_io(driver,data);
    return i;
}
