#include "drivers/tty/n_tty.h"

#include "errno.h"

#include "drivers/tty/driver.h"
#include "drivers/tty/ldisc.h"
#include "drivers/tty/tty.h"

#include "mm/kmalloc.h"

#include "proc/kthread.h"

#include "util/debug.h"

/* helpful macros */
#define EOFC            '\x4'
#define TTY_BUF_SIZE    128
#define ldisc_to_ntty(ldisc) \
        CONTAINER_OF(ldisc, n_tty_t, ntty_ldisc)
#define IS_NEWLINE(c) (((c) == '\r') || (c == '\n'))
#define IS_BACKSPACE(c) (((c) == 0x08) || ((c) == 0x7F))
#define IS_ECS(c) (((c) == 0x04))
#define SPACE 0x20

static void n_tty_attach(tty_ldisc_t *ldisc, tty_device_t *tty);
static void n_tty_detach(tty_ldisc_t *ldisc, tty_device_t *tty);
static int n_tty_read(tty_ldisc_t *ldisc, void *buf, int len);
static const char *n_tty_receive_char(tty_ldisc_t *ldisc, char c);
static const char *n_tty_process_char(tty_ldisc_t *ldisc, char c);

static tty_ldisc_ops_t n_tty_ops = {
        .attach       = n_tty_attach,
        .detach       = n_tty_detach,
        .read         = n_tty_read,
        .receive_char = n_tty_receive_char,
        .process_char = n_tty_process_char
};

struct n_tty {
        kmutex_t            ntty_rlock;
        ktqueue_t           ntty_rwaitq;
        char               *ntty_inbuf;
        int                 ntty_rhead;
        int                 ntty_rawtail;
        int                 ntty_ckdtail;

        tty_ldisc_t         ntty_ldisc;
};


tty_ldisc_t *
n_tty_create()
{
        n_tty_t *ntty = (n_tty_t *)kmalloc(sizeof(n_tty_t));
        if (NULL == ntty) return NULL;
        ntty->ntty_ldisc.ld_ops = &n_tty_ops;
        return &ntty->ntty_ldisc;
}

void
n_tty_destroy(tty_ldisc_t *ldisc)
{
        KASSERT(NULL != ldisc);
        kfree(ldisc_to_ntty(ldisc));
}

/*
 * Initialize the fields of the n_tty_t struct, allocate any memory
 * you will need later, and set the tty_ldisc field of the tty.
 */
void
n_tty_attach(tty_ldisc_t *ldisc, tty_device_t *tty)
{
        KASSERT(ldisc != NULL);
        KASSERT(tty != NULL);
        n_tty_t *ntty = ldisc_to_ntty(ldisc);
        /* init the attributes in ntty */
        kmutex_init(&ntty->ntty_rlock);
        sched_queue_init(&ntty->ntty_rwaitq);
        ntty->ntty_inbuf = (char*) kmalloc(TTY_BUF_SIZE);
        if(ntty->ntty_inbuf == NULL) {
                panic("Not enough memory for inbuf\n");
        }
        ntty->ntty_rhead = 0;
        ntty->ntty_rawtail = 0;
        ntty->ntty_ckdtail = 0;

        tty->tty_ldisc = ldisc;
}

/*
 * Free any memory allocated in n_tty_attach and set the tty_ldisc
 * field of the tty.
 */
void
n_tty_detach(tty_ldisc_t *ldisc, tty_device_t *tty)
{
        KASSERT(ldisc != NULL);
        KASSERT(tty != NULL);
        n_tty_t *ntty = ldisc_to_ntty(ldisc);
        KASSERT(ntty->ntty_inbuf != NULL);
        kfree(ntty->ntty_inbuf);       
        tty->tty_ldisc = ldisc;  // ?
}


static int buf_empty(n_tty_t *ntty) {
        return (ntty->ntty_rhead == ntty->ntty_ckdtail);
}

static int buf_full(n_tty_t *ntty) {
        return ((ntty->ntty_rawtail + 1) % TTY_BUF_SIZE == ntty->ntty_rhead);
}

static int buf_has_raw(n_tty_t *ntty) {
        return ntty->ntty_rawtail != ntty->ntty_ckdtail;
}

/*
 * Read a maximum of len bytes from the line discipline into buf. If
 * the buffer is empty, sleep until some characters appear. This might
 * be a long wait, so it's best to let the thread be cancellable.
 * Return -EINTR when the thread gets cancelled.
 *
 * Then, read from the head of the buffer up to the tail, stopping at
 * len bytes or a newline character, and leaving the buffer partially
 * full if necessary. Return the number of bytes you read into the
 * buf.

 * In this function, you will be accessing the input buffer, which
 * could be modified by other threads. Make sure to make the
 * appropriate calls to ensure that no one else will modify the input
 * buffer when we are not expecting it.
 *
 * Remember to handle newline characters and CTRL-D, or ASCII 0x04,
 * properly.
 */
int
n_tty_read(tty_ldisc_t *ldisc, void *buf, int len)
{
        KASSERT(ldisc != NULL);
        KASSERT(buf != NULL);
        char* buffer = (char*) buf;
        n_tty_t *ntty = ldisc_to_ntty(ldisc);

        kmutex_lock(&ntty->ntty_rlock);

        int buf_pos = 0;
        int bytes_read = 0;
        char cur_char = '\0';
        while(bytes_read < len && !IS_NEWLINE(cur_char)) {
                if(buf_empty(ntty)) {
                        sched_cancellable_sleep_on(&ntty->ntty_rwaitq);

                        /* getting here means we are cancelled */
                        if(buf_empty(ntty)) {
                                kmutex_unlock(&ntty->ntty_rlock);
                                return -EINTR;
                        }
                }

                KASSERT(!buf_empty(ntty));
                ntty->ntty_rhead = (ntty->ntty_rhead + 1) % TTY_BUF_SIZE;
                cur_char = ntty->ntty_inbuf[ntty->ntty_rhead];

                if(!IS_ECS(cur_char)) {
                        buffer[buf_pos++] = cur_char;
                }
                bytes_read++;
        }
        kmutex_unlock(&ntty->ntty_rlock);
        return bytes_read;
}

/*
 * The tty subsystem calls this when the tty driver has received a
 * character. Now, the line discipline needs to store it in its read
 * buffer and move the read tail forward.
 *
 * Special cases to watch out for: backspaces (both ASCII characters
 * 0x08 and 0x7F should be treated as backspaces), newlines ('\r' or
 * '\n'), and full buffers. 
 * Hints: For newlines (either '\r' or '\n'), you
 * need to return '\r\n' to make it display successfully (carriage 
 * return, followed by a line feed).
 *
 * Return a null terminated string containing the characters which
 * need to be echoed to the screen. For a normal, printable character,
 * just the character to be echoed.
 */
const char *
n_tty_receive_char(tty_ldisc_t *ldisc, char c)
{
        n_tty_t *ntty = ldisc_to_ntty(ldisc);

        const char* ret = n_tty_process_char(ldisc, c);
        /* if it is a backspace */
        if(IS_BACKSPACE(c)) {
                if(buf_has_raw(ntty)) {
                        ntty->ntty_rawtail = (ntty->ntty_rawtail - 1) % TTY_BUF_SIZE;
                }
        } else if(buf_full(ntty)) {
                /* do nothing */
        } else if(IS_NEWLINE(c)){
                /* if it is a new line, move cooked tail pointer as well */
                ntty->ntty_rawtail = (ntty->ntty_rawtail + 1) % TTY_BUF_SIZE;
                ntty->ntty_ckdtail = ntty->ntty_rawtail;
                ntty->ntty_inbuf[ntty->ntty_rawtail] = c;
                sched_wakeup_on(&ntty->ntty_rwaitq);
        } else {
                ntty->ntty_rawtail = (ntty->ntty_rawtail + 1) % TTY_BUF_SIZE;
                ntty->ntty_inbuf[ntty->ntty_rawtail] = c;
        }
        return ret;
}

/*
 * Process a character to be written to the screen.
 *
 * The only special case is '\r' and '\n'. Weenix needs
 * '\r\n' to make a new line on screen.
 */
const char *
n_tty_process_char(tty_ldisc_t *ldisc, char c)
{
        n_tty_t *ntty = ldisc_to_ntty(ldisc);
        char *ret;
        if(IS_BACKSPACE(c)) {
                if(!buf_has_raw(ntty)) return NULL;

                ret = kmalloc(4 * sizeof(char));
                if(ret == NULL) return NULL;
                ret[0] = c;
                ret[1] = SPACE;
                ret[2] = c;
                ret[3] = '\0';
        }
        else if(buf_full(ntty)) {
                ret = kmalloc(sizeof(char));
                if(ret == NULL) return NULL;
                ret[0] = '\0';
        } else if(IS_NEWLINE(c)) {
                ret = kmalloc(3*sizeof(char));
                if(ret == NULL) return NULL;
                ret[0] = '\r';
                ret[1] = '\n';
                ret[2] = '\0';
        } else{
                ret = kmalloc(2*sizeof(char));
                if(ret == NULL) return NULL;
                ret[0] = c;
                ret[1] = '\0';
        } 
        return ret;
}
