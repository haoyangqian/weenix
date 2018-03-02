#include "kernel.h"
#include "globals.h"
#include "types.h"
#include "errno.h"

#include "util/string.h"
#include "util/printf.h"
#include "util/debug.h"

#include "fs/dirent.h"
#include "fs/fcntl.h"
#include "fs/stat.h"
#include "fs/vfs.h"
#include "fs/vnode.h"

/* This takes a base 'dir', a 'name', its 'len', and a result vnode.
 * Most of the work should be done by the vnode's implementation
 * specific lookup() function.
 *
 * If dir has no lookup(), return -ENOTDIR.
 *
 * Note: returns with the vnode refcount on *result incremented.
 */
int
lookup(vnode_t *dir, const char *name, size_t len, vnode_t **result)
{
    KASSERT(dir != NULL);
    if(dir->vn_ops->lookup == NULL) {
        return -ENOTDIR;
    }

    KASSERT(name != NULL);
    int ret = dir->vn_ops->lookup(dir, name, len, result);
    return ret;
}


/* When successful this function returns data in the following "out"-arguments:
 *  o res_vnode: the vnode of the parent directory of "name"
 *  o name: the `basename' (the element of the pathname)
 *  o namelen: the length of the basename
 *
 * For example: dir_namev("/s5fs/bin/ls", &namelen, &name, NULL,
 * &res_vnode) would put 2 in namelen, "ls" in name, and a pointer to the
 * vnode corresponding to "/s5fs/bin" in res_vnode.
 *
 * The "base" argument defines where we start resolving the path from:
 * A base value of NULL means to use the process's current working directory,
 * curproc->p_cwd.  If pathname[0] == '/', ignore base and start with
 * vfs_root_vn.  dir_namev() should call lookup() to take care of resolving each
 * piece of the pathname.
 *
 * Note: A successful call to this causes vnode refcount on *res_vnode to
 * be incremented.
 */
int
dir_namev(const char *pathname, size_t *namelen, const char **name,
          vnode_t *base, vnode_t **res_vnode)
{
        /* the pathname starts with '\0'*/
        if(*pathname == '\0') {
            return -EINVAL;
        }

        vnode_t *parent = NULL;
        vnode_t *current = NULL;
        if(*pathname == '/') {
            current = vfs_root_vn;

            while(*pathname == '/') pathname++;
        } else if(base == NULL){
            current = curproc->p_cwd;
        } else {
            current = base;
        }

        KASSERT(current != NULL);

        vref(current);

        /* the pathname starts with '\0'*/
        if(*pathname == '\0') {
            *namelen = 1;
            *name = ".";
            *res_vnode = current;
            return 0;
        }

        int lookup_result = 1;
        int current_start = 0;
        int prev_start = 0;
        size_t len = 0;
        int errorcode;
        while(lookup_result >= 0 && pathname[current_start]!= '\0') {
            if(parent != NULL) {
                vput(parent);
            }

            parent = current;
            len = 0;
            while(pathname[current_start + len] != '/' && pathname[current_start + len] != '\0') {
                len++;
            }

            dbg(DBG_VFS, "lookup_result: %d current_start:%d len:%d\n",lookup_result, current_start, len);

            if(len > NAME_LEN) {
                errorcode = -ENAMETOOLONG;
                break;
            } 

            lookup_result = lookup(parent, (pathname + current_start), len, &current);

            if(lookup_result == -ENOTDIR) {
                errorcode = -ENOTDIR;
                break;
            }

            prev_start = current_start;
            current_start += len;

            /* remove any trailing zeros*/
            while(pathname[current_start] == '/') {
                current_start++;
            }
        }

        /* check the error code*/
        if (lookup_result < 0 && lookup_result != -ENOENT){
            dbg(DBG_VFS, "lookup failed with error code %d\n", lookup_result);
            vput(parent);

            return lookup_result;
        } else if (errorcode != 0){
            dbg(DBG_VFS, "lookup failed with error code %d\n", errorcode);
            vput(parent);

            return errorcode;
        } else if (pathname[next_name] != '\0'){
            KASSERT(lookup_result == -ENOENT);
            dbg(DBG_VFS, "lookup failed with error code %d\n", -ENOENT);

            vput(parent);
            return -ENOENT;
        }

        if(lookup_result == 0) {
            vput(current);
        }

        *namelen = len;
        *name = pathname + prev_start;
        *res_vnode = parent;
        
        return 0;
}

/* This returns in res_vnode the vnode requested by the other parameters.
 * It makes use of dir_namev and lookup to find the specified vnode (if it
 * exists).  flag is right out of the parameters to open(2); see
 * <weenix/fcntl.h>.  If the O_CREAT flag is specified and the file does
 * not exist, call create() in the parent directory vnode. However, if the
 * parent directory itself does not exist, this function should fail - in all
 * cases, no files or directories other than the one at the very end of the path
 * should be created.
 *
 * Note: Increments vnode refcount on *res_vnode.
 */
int
open_namev(const char *pathname, int flag, vnode_t **res_vnode, vnode_t *base)
{
        NOT_YET_IMPLEMENTED("VFS: open_namev");
        return 0;
}

#ifdef __GETCWD__
/* Finds the name of 'entry' in the directory 'dir'. The name is writen
 * to the given buffer. On success 0 is returned. If 'dir' does not
 * contain 'entry' then -ENOENT is returned. If the given buffer cannot
 * hold the result then it is filled with as many characters as possible
 * and a null terminator, -ERANGE is returned.
 *
 * Files can be uniquely identified within a file system by their
 * inode numbers. */
int
lookup_name(vnode_t *dir, vnode_t *entry, char *buf, size_t size)
{
        NOT_YET_IMPLEMENTED("GETCWD: lookup_name");
        return -ENOENT;
}


/* Used to find the absolute path of the directory 'dir'. Since
 * directories cannot have more than one link there is always
 * a unique solution. The path is writen to the given buffer.
 * On success 0 is returned. On error this function returns a
 * negative error code. See the man page for getcwd(3) for
 * possible errors. Even if an error code is returned the buffer
 * will be filled with a valid string which has some partial
 * information about the wanted path. */
ssize_t
lookup_dirpath(vnode_t *dir, char *buf, size_t osize)
{
        NOT_YET_IMPLEMENTED("GETCWD: lookup_dirpath");

        return -ENOENT;
}
#endif /* __GETCWD__ */
