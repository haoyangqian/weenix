#include "errno.h"
#include "globals.h"

#include "util/string.h"
#include "util/debug.h"

#include "mm/mm.h"
#include "mm/page.h"
#include "mm/mmobj.h"
#include "mm/kmalloc.h"
#include "mm/pframe.h"

#include "drivers/bytedev.h"

#include "vm/anon.h"

#include "fs/vnode.h"

static int null_read(bytedev_t *dev, int offset, void *buf, int count);
static int null_write(bytedev_t *dev, int offset, const void *buf, int count);

static int zero_read(bytedev_t *dev, int offset, void *buf, int count);
static int zero_mmap(vnode_t *file, vmarea_t *vma, mmobj_t **ret);

bytedev_ops_t null_dev_ops = {
        null_read,
        null_write,
        NULL,
        NULL,
        NULL,
        NULL
};

bytedev_ops_t zero_dev_ops = {
        zero_read,
        null_write,
        zero_mmap,
        NULL,
        NULL,
        NULL
};

/*
 * The byte device code needs to know about these mem devices, so create
 * bytedev_t's for null and zero, fill them in, and register them.
 */
void
memdevs_init()
{
        /* init and register null dev */
        bytedev_t *null_dev = (bytedev_t*) kmalloc(sizeof(bytedev_t));
        KASSERT(null_dev != NULL && "can not malloc null dev");

        null_dev->cd_id = MEM_NULL_DEVID;
        null_dev->cd_ops = &null_dev_ops;
        list_link_init(&null_dev->cd_link);

        bytedev_register(null_dev);

        /* init and register zero dev */
        bytedev_t *zero_dev = (bytedev_t*) kmalloc(sizeof(bytedev_t));
        KASSERT(zero_dev != NULL && "can not malloc zero dev");

        zero_dev->cd_id = MEM_ZERO_DEVID;
        zero_dev->cd_ops = &zero_dev_ops;
        list_link_init(&zero_dev->cd_link);

        bytedev_register(zero_dev);

}

/**
 * Reads a given number of bytes from the null device into a
 * buffer. Any read performed on the null device should read 0 bytes.
 *
 * @param dev the null device
 * @param offset the offset to read from. Should be ignored
 * @param buf the buffer to read into
 * @param count the maximum number of bytes to read
 * @return the number of bytes read, which should be 0
 */
static int
null_read(bytedev_t *dev, int offset, void *buf, int count)
{
        return 0;
}

/**
 * Writes a given number of bytes to the null device from a
 * buffer. Writing to the null device should _ALWAYS_ be successful
 * and write the maximum number of bytes.
 *
 * @param dev the null device
 * @param offset the offset to write to. Should be ignored
 * @param buf buffer to read from
 * @param count the maximum number of bytes to write
 * @return the number of bytes written, which should be count
 */
static int
null_write(bytedev_t *dev, int offset, const void *buf, int count)
{
        return count;
}

/**
 * Reads a given number of bytes from the zero device into a
 * buffer. Any read from the zero device should be a series of zeros.
 *
 * @param dev the zero device
 * @param offset the offset to read from. Should be ignored
 * @param buf the buffer to write to
 * @param count the maximum number of bytes to read
 * @return the number of bytes read. Should always read the maximum
 * number of bytes
 */
static int
zero_read(bytedev_t *dev, int offset, void *buf, int count)
{
        char* buffer = (char*) buf;
        int i;
        for(i = 0;i < count;++i) {
                buffer[i] = '\0';
        }
        return count;
}

/* Don't worry about these until VM. Once you're there, they shouldn't be hard. */

static int
zero_mmap(vnode_t *file, vmarea_t *vma, mmobj_t **ret)
{
        mmobj_t *obj = anon_create();

        if (obj == NULL){
                return -ENOMEM;
        }

        *ret = obj;
        return 0;
}
