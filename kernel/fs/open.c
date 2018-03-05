/*
 *  FILE: open.c
 *  AUTH: mcc | jal
 *  DESC:
 *  DATE: Mon Apr  6 19:27:49 1998
 */

#include "globals.h"
#include "errno.h"
#include "fs/fcntl.h"
#include "util/string.h"
#include "util/printf.h"
#include "fs/vfs.h"
#include "fs/vnode.h"
#include "fs/file.h"
#include "fs/vfs_syscall.h"
#include "fs/open.h"
#include "fs/stat.h"
#include "util/debug.h"

/* find empty index in p->p_files[] */
int
get_empty_fd(proc_t *p)
{
        int fd;

        for (fd = 0; fd < NFILES; fd++) {
                if (!p->p_files[fd])
                        return fd;
        }

        dbg(DBG_ERROR | DBG_VFS, "ERROR: get_empty_fd: out of file descriptors "
            "for pid %d\n", curproc->p_pid);
        return -EMFILE;
}

/*
 * There a number of steps to opening a file:
 *      1. Get the next empty file descriptor.
 *      2. Call fget to get a fresh file_t.
 *      3. Save the file_t in curproc's file descriptor table.
 *      4. Set file_t->f_mode to OR of FMODE_(READ|WRITE|APPEND) based on
 *         oflags, which can be O_RDONLY, O_WRONLY or O_RDWR, possibly OR'd with
 *         O_APPEND.
 *      5. Use open_namev() to get the vnode for the file_t.
 *      6. Fill in the fields of the file_t.
 *      7. Return new fd.
 *
 * If anything goes wrong at any point (specifically if the call to open_namev
 * fails), be sure to remove the fd from curproc, fput the file_t and return an
 * error.
 *
 * Error cases you must handle for this function at the VFS level:
 *      o EINVAL
 *        oflags is not valid.
 *      o EMFILE
 *        The process already has the maximum number of files open.
 *      o ENOMEM
 *        Insufficient kernel memory was available.
 *      o ENAMETOOLONG
 *        A component of filename was too long.
 *      o ENOENT
 *        O_CREAT is not set and the named file does not exist.  Or, a
 *        directory component in pathname does not exist.
 *      o EISDIR
 *        pathname refers to a directory and the access requested involved
 *        writing (that is, O_WRONLY or O_RDWR is set).
 *      o ENXIO
 *        pathname refers to a device special file and no corresponding device
 *        exists.
 */

int
do_open(const char *filename, int oflags)
{
        /* 1. get the next empty file descriptor */
        int fd = get_empty_fd(curproc);

        if(fd < 0) {
            return -EMFILE;
        }

        /* 2. call fget to get a fresh file_t */
        file_t *file = fget(-1);

        if(file == NULL) {
            return -ENOMEM;
        }

        KASSERT(file != NULL);
        KASSERT(file->f_refcount == 1);
        
        /* 3. Save the file_t in curproc's file descriptor table. */
        KASSERT(curproc->p_files[fd] == NULL);
        curproc->p_files[fd] = file;

        /* 4. Set file_t->f_mode to OR of FMODE_(READ|WRITE|APPEND) based on
        *  oflags, which can be O_RDONLY, O_WRONLY or O_RDWR, possibly OR'd with
        *  O_APPEND. */
        file->f_mode = 0;
        if(oflags & O_APPEND) {
            file->f_mode = FMODE_APPEND;
        }

        if( (oflags & O_WRONLY) && !(oflags & O_RDWR)) {
            file->f_mode |= FMODE_WRITE;
        } else if((oflags & O_RDWR) && !(oflags & O_WRONLY)) {
            file->f_mode |=  FMODE_READ | FMODE_WRITE;
        } else if(oflags == O_RDONLY || oflags == (O_RDONLY | O_CREAT)
            || oflags == (O_RDONLY | O_APPEND)
            || oflags == (O_RDONLY | O_CREAT | O_APPEND)) {
            file->f_mode |= FMODE_READ;
        } else {
            dbg(DBG_VFS, "oflags is not valid.");
            fput(file);
            curproc->p_files[fd] = NULL;
            return -EINVAL;
        }

        /* 5. Use open_namev() to get the vnode for the file_t. */
        int open_ret = open_namev(filename, oflags, &file->f_vnode, NULL);
        if(open_ret < 0) {
            curproc->p_files[fd] = NULL;
            fput(file);
            return open_ret;
        }

        /* 6. Fill in the fields of the file_t.*/
        file->f_pos = 0;
        file->f_refcount = 1;

        /* 7. Return new fd */
        return fd;

}
