/*
 *   FILE: s5fs_subr.c
 * AUTHOR: afenn
 *  DESCR:
 *  $Id: s5fs_subr.c,v 1.1.2.1 2006/06/04 01:02:15 afenn Exp $
 */

#include "kernel.h"
#include "util/debug.h"
#include "mm/kmalloc.h"
#include "globals.h"
#include "proc/sched.h"
#include "proc/kmutex.h"
#include "errno.h"
#include "util/string.h"
#include "util/printf.h"
#include "mm/pframe.h"
#include "mm/mmobj.h"
#include "drivers/dev.h"
#include "drivers/blockdev.h"
#include "fs/stat.h"
#include "fs/vfs.h"
#include "fs/vnode.h"
#include "fs/s5fs/s5fs_subr.h"
#include "fs/s5fs/s5fs.h"
#include "mm/mm.h"
#include "mm/page.h"

#define dprintf(...) dbg(DBG_S5FS, __VA_ARGS__)

#define s5_dirty_super(fs)                                           \
        do {                                                         \
                pframe_t *p;                                         \
                int err;                                             \
                pframe_get(S5FS_TO_VMOBJ(fs), S5_SUPER_BLOCK, &p);   \
                KASSERT(p);                                          \
                err = pframe_dirty(p);                               \
                KASSERT(!err                                         \
                        && "shouldn\'t fail for a page belonging "   \
                        "to a block device");                        \
        } while (0)

#define NDIRENTS 5
static void s5_free_block(s5fs_t *fs, int block);
static int s5_alloc_block(s5fs_t *);


/*
 * Return the disk-block number for the given seek pointer (aka file
 * position).
 *
 * If the seek pointer refers to a sparse block, and alloc is false,
 * then return 0. If the seek pointer refers to a sparse block, and
 * alloc is true, then allocate a new disk block (and make the inode
 * point to it) and return it.
 *
 * Be sure to handle indirect blocks!
 *
 * If there is an error, return -errno.
 *
 * You probably want to use s5_alloc_block, pframe_get, pframe_pin, 
 * pframe_unpin, pframe_dirty.
 */
int
s5_seek_to_block(vnode_t *vnode, off_t seekptr, int alloc)
{
    KASSERT(vnode != NULL);
    uint32_t block_index = S5_DATA_BLOCK(seekptr);

    // if the block index is beyond the maximum limit
    if(block_index >= S5_MAX_FILE_BLOCKS) {
        return -EFBIG;
    }

    if(seekptr > vnode->vn_len && !alloc) {
        return 0;
    }

    s5_inode_t *inode = VNODE_TO_S5INODE(vnode);

    uint32_t seek_block_num;

    /* if the block that we are seeking should be an indirect block */
    if(block_index >= S5_NDIRECT_BLOCKS) {
        pframe_t *pageframe;
        mmobj_t *mmo = S5FS_TO_VMOBJ(VNODE_TO_S5FS(vnode));

        /* if we have no indirect block */
        if(inode->s5_indirect_block == 0) {

            if(!alloc) return 0;

            // if alloc is true, we should allocate a new indirect block
            static int zero_array[BLOCK_SIZE] = {};

            /* first, get an indirect block */
            int indirect_block = s5_alloc_block(VNODE_TO_S5FS(vnode));
            if(indirect_block < 0) {
                dbg(DBG_S5FS, "unable to alloc an indirect block.\n");
            }

            /* then, zero it */
            int get_res = pframe_get(mmo, inode->s5_indirect_block, &pageframe);
            if(get_res < 0) return get_res;

            memcpy(pageframe->pf_addr, zero_array, BLOCK_SIZE);

            int dirty_res = pframe_dirty(pageframe);
            if(dirty_res < 0) return dirty_res;

            /* finally, set the inode */
            inode->s5_indirect_block = indirect_block;
            s5_dirty_inode(VNODE_TO_S5FS(vnode), inode);
        }

        // now we have the indirect block, so get the pframe object of it
        if(pframe_get(mmo, inode->s5_indirect_block, &pageframe) < 0) {
            panic("failed to get the pframe.\n");
        }

        // get the block num that we are seeking
        seek_block_num = ((uint32_t*) pageframe->pf_addr)[block_index - S5_NDIRECT_BLOCKS];

        // when found a sparse block and want to alloc it
        if(seek_block_num == 0 && alloc) {
            pframe_pin(pageframe);
            int block_num = s5_alloc_block(VNODE_TO_S5FS(vnode));
            pframe_unpin(pageframe);

            if(block_num < 0){
                dbg(DBG_S5FS, "unable to alloc a sparse block.\n");
                return block_num;
            }

            seek_block_num = block_num;
            // set the pageframe to the new block_num
            ((uint32_t *) pageframe->pf_addr)[block_index - S5_NDIRECT_BLOCKS] = seek_block_num;

            // mark the pframe as dirty
            int dirty_res = pframe_dirty(pageframe);

            if(dirty_res < 0) return dirty_res;
        }
    } else {
        // if the block we are seeking is not indirect block
        seek_block_num = inode->s5_direct_blocks[block_index];

        // when found a sparse block and want to alloc it
        if(seek_block_num == 0 && alloc) {
            int block_num = s5_alloc_block(VNODE_TO_S5FS(vnode));
            if(block_num < 0){
                dbg(DBG_S5FS, "unable to alloc a sparse block.\n");
                return block_num;
            }

            seek_block_num = block_num;
            inode->s5_direct_blocks[block_index] = seek_block_num;
            s5_dirty_inode(VNODE_TO_S5FS(vnode), inode);
        }
    }
    return seek_block_num;
}


/*
 * Locks the mutex for the whole file system
 */
static void
lock_s5(s5fs_t *fs)
{
        kmutex_lock(&fs->s5f_mutex);
}

/*
 * Unlocks the mutex for the whole file system
 */
static void
unlock_s5(s5fs_t *fs)
{
        kmutex_unlock(&fs->s5f_mutex);
}


/*
 * Write len bytes to the given inode, starting at seek bytes from the
 * beginning of the inode. On success, return the number of bytes
 * actually written (which should be 'len', unless there's only enough
 * room for a partial write); on failure, return -errno.
 *
 * This function should allow writing to files or directories, treating
 * them identically.
 *
 * Writing to a sparse block of the file should cause that block to be
 * allocated.  Writing past the end of the file should increase the size
 * of the file. Blocks between the end and where you start writing will
 * be sparse. In addition, bytes between where the old end of the file was and
 * the beginning of where you start writing should also be null.
 *
 * You cannot count on the contents of a block being null. Thus, if the seek
 * offset is not block aligned, be sure to set to null everything from where the
 * file ended to where the write begins.
 *
 * Do not call s5_seek_to_block() directly from this function.  You will
 * use the vnode's pframe functions, which will eventually result in a
 * call to s5_seek_to_block().
 *
 * You will need pframe_dirty(), pframe_get(), memcpy().
 */
int
s5_write_file(vnode_t *vnode, off_t seek, const char *bytes, size_t len)
{
    KASSERT(vnode != NULL && bytes != NULL);

    if(seek < 0) return -EINVAL;

    if(seek + len >= S5_MAX_FILE_BLOCKS) {
        len = S5_MAX_FILE_BLOCKS - seek - 1;
    }

    off_t pos = 0;
    off_t end_pos = seek + len; 
    int get_res = 0;
    int write_size;
    int err = 0;
    mmobj_t *mmo = &vnode->vn_mmobj;
    pframe_t *pageframe;

    while(pos < (off_t)len) {
        /* within a block, get the block index and offset */
        int block_index = S5_DATA_BLOCK(seek);
        off_t offset = S5_DATA_OFFSET(seek);

        get_res = pframe_get(mmo, block_index, &pageframe);
        if(get_res < 0) {
            err = get_res;
            break;
        }

        write_size = MIN((off_t)PAGE_SIZE - offset, end_pos - seek);

        KASSERT(write_size >= 0);

        memcpy((char*) pageframe->pf_addr + offset, (void *) (bytes + pos), write_size);

        int dirty_res = pframe_dirty(pageframe);
        if(dirty_res < 0) {
            err = dirty_res;
            break;
        }

        seek += write_size;
        pos += write_size;
    }

    /* if we need to extend the file. */
    if(seek > vnode->vn_len) {
        s5_inode_t *inode = VNODE_TO_S5INODE(vnode);
        vnode->vn_len = seek;
        inode->s5_size = vnode->vn_len;
        s5_dirty_inode(VNODE_TO_S5FS(vnode), inode);
    }

    return err? err : pos;
}

/*
 * Read up to len bytes from the given inode, starting at seek bytes
 * from the beginning of the inode. On success, return the number of
 * bytes actually read, or 0 if the end of the file has been reached; on
 * failure, return -errno.
 *
 * This function should allow reading from files or directories,
 * treating them identically.
 *
 * Reading from a sparse block of the file should act like reading
 * zeros; it should not cause the sparse blocks to be allocated.
 *
 * Similarly as in s5_write_file(), do not call s5_seek_to_block()
 * directly from this function.
 *
 * If the region to be read would extend past the end of the file, less
 * data will be read than was requested.
 *
 * You probably want to use pframe_get(), memcpy().
 */
int
s5_read_file(struct vnode *vnode, off_t seek, char *dest, size_t len)
{
    KASSERT(vnode != NULL && dest != NULL);

    if(seek < 0) return -EINVAL;
    if(seek >= vnode->vn_len) return 0;

    off_t end_pos = MIN(seek + (off_t)len, vnode->vn_len);
    len = end_pos - seek;
    off_t pos = 0;
    int get_res = 0;
    int read_size;
    int err = 0;
    mmobj_t *mmo = &vnode->vn_mmobj;
    pframe_t *pageframe;

    while(pos < (off_t)len) {
        /* within a block, get the block index and offset */
        int block_index = S5_DATA_BLOCK(seek);
        off_t offset = S5_DATA_OFFSET(seek);

        get_res = pframe_get(mmo, block_index, &pageframe);
        if(get_res < 0) {
            err = get_res;
            break;
        }

        read_size = MIN((off_t)PAGE_SIZE - offset, end_pos - seek);

        KASSERT(read_size > 0);

        memcpy((void *) (dest + pos), (char*) pageframe->pf_addr + offset, read_size);

        pos += read_size;
        seek += read_size;
    }
    return err ? err : pos;
}

/*
 * Allocate a new disk-block off the block free list and return it. If
 * there are no free blocks, return -ENOSPC.
 *
 * This will not initialize the contents of an allocated block; these
 * contents are undefined.
 *
 * If the super block's s5s_nfree is 0, you need to refill
 * s5s_free_blocks and reset s5s_nfree.  You need to read the contents
 * of this page using the pframe system in order to obtain the next set of
 * free block numbers.
 *
 * Don't forget to dirty the appropriate blocks!
 *
 * You'll probably want to use lock_s5(), unlock_s5(), pframe_get(),
 * and s5_dirty_super()
 */
static int
s5_alloc_block(s5fs_t *fs)
{
    s5_super_t *s = fs->s5f_super;

    lock_s5(fs);

    KASSERT(S5_NBLKS_PER_FNODE > s->s5s_nfree);

    int free_block_num;

    /* if there is no free block in freelist */
    if(s->s5s_nfree == 0) {
        // get the last block
        free_block_num = s->s5s_free_blocks[S5_NBLKS_PER_FNODE - 1];

        if(free_block_num == -1) {
            unlock_s5(fs);
            return -ENOSPC;
        }

        /* get the pframe of the last block */
        pframe_t *new_free_blocks;
        KASSERT(fs->s5f_bdev);
        int get_res = pframe_get(&fs->s5f_bdev->bd_mmobj, free_block_num, &new_free_blocks);
        if(get_res < 0) {
            unlock_s5(fs);
            return get_res;
        }

        memcpy((void*) s->s5s_free_blocks, new_free_blocks->pf_addr, S5_NBLKS_PER_FNODE*sizeof(int));
        s->s5s_nfree = S5_NBLKS_PER_FNODE - 1;
    } else {
        free_block_num = s->s5s_free_blocks[--s->s5s_nfree];
    }

    s5_dirty_super(fs);

    unlock_s5(fs);

    return free_block_num;
}


/*
 * Given a filesystem and a block number, frees the given block in the
 * filesystem.
 *
 * This function may potentially block.
 *
 * The caller is responsible for ensuring that the block being placed on
 * the free list is actually free and is not resident.
 */
static void
s5_free_block(s5fs_t *fs, int blockno)
{
        s5_super_t *s = fs->s5f_super;


        lock_s5(fs);

        KASSERT(S5_NBLKS_PER_FNODE > s->s5s_nfree);

        if ((S5_NBLKS_PER_FNODE - 1) == s->s5s_nfree) {
                /* get the pframe where we will store the free block nums */
                pframe_t *prev_free_blocks = NULL;
                KASSERT(fs->s5f_bdev);
                pframe_get(&fs->s5f_bdev->bd_mmobj, blockno, &prev_free_blocks);
                KASSERT(prev_free_blocks->pf_addr);

                /* copy from the superblock to the new block on disk */
                memcpy(prev_free_blocks->pf_addr, (void *)(s->s5s_free_blocks),
                       S5_NBLKS_PER_FNODE * sizeof(int));
                KASSERT(pframe_dirty(prev_free_blocks) == 0);

                /* reset s->s5s_nfree and s->s5s_free_blocks */
                s->s5s_nfree = 0;
                s->s5s_free_blocks[S5_NBLKS_PER_FNODE - 1] = blockno;
        } else {
                s->s5s_free_blocks[s->s5s_nfree++] = blockno;
        }

        s5_dirty_super(fs);

        unlock_s5(fs);
}

/*
 * Creates a new inode from the free list and initializes its fields.
 * Uses S5_INODE_BLOCK to get the page from which to create the inode
 *
 * This function may block.
 */
int
s5_alloc_inode(fs_t *fs, uint16_t type, devid_t devid)
{
        s5fs_t *s5fs = FS_TO_S5FS(fs);
        pframe_t *inodep;
        s5_inode_t *inode;
        int ret = -1;

        KASSERT((S5_TYPE_DATA == type)
                || (S5_TYPE_DIR == type)
                || (S5_TYPE_CHR == type)
                || (S5_TYPE_BLK == type));


        lock_s5(s5fs);

        if (s5fs->s5f_super->s5s_free_inode == (uint32_t) -1) {
                unlock_s5(s5fs);
                return -ENOSPC;
        }

        pframe_get(&s5fs->s5f_bdev->bd_mmobj,
                   S5_INODE_BLOCK(s5fs->s5f_super->s5s_free_inode),
                   &inodep);
        KASSERT(inodep);

        inode = (s5_inode_t *)(inodep->pf_addr)
                + S5_INODE_OFFSET(s5fs->s5f_super->s5s_free_inode);

        KASSERT(inode->s5_number == s5fs->s5f_super->s5s_free_inode);

        ret = inode->s5_number;

        /* reset s5s_free_inode; remove the inode from the inode free list: */
        s5fs->s5f_super->s5s_free_inode = inode->s5_next_free;
        pframe_pin(inodep);
        s5_dirty_super(s5fs);
        pframe_unpin(inodep);


        /* init the newly-allocated inode: */
        inode->s5_size = 0;
        inode->s5_type = type;
        inode->s5_linkcount = 0;
        memset(inode->s5_direct_blocks, 0, S5_NDIRECT_BLOCKS * sizeof(int));
        if ((S5_TYPE_CHR == type) || (S5_TYPE_BLK == type))
                inode->s5_indirect_block = devid;
        else
                inode->s5_indirect_block = 0;

        s5_dirty_inode(s5fs, inode);

        unlock_s5(s5fs);

        return ret;
}


/*
 * Free an inode by freeing its disk blocks and putting it back on the
 * inode free list.
 *
 * You should also reset the inode to an unused state (eg. zero-ing its
 * list of blocks and setting its type to S5_FREE_TYPE).
 *
 * Don't forget to free the indirect block if it exists.
 *
 * You probably want to use s5_free_block().
 */
void
s5_free_inode(vnode_t *vnode)
{
        uint32_t i;
        s5_inode_t *inode = VNODE_TO_S5INODE(vnode);
        s5fs_t *fs = VNODE_TO_S5FS(vnode);

        KASSERT((S5_TYPE_DATA == inode->s5_type)
                || (S5_TYPE_DIR == inode->s5_type)
                || (S5_TYPE_CHR == inode->s5_type)
                || (S5_TYPE_BLK == inode->s5_type));

        /* free any direct blocks */
        for (i = 0; i < S5_NDIRECT_BLOCKS; ++i) {
                if (inode->s5_direct_blocks[i]) {
                        dprintf("freeing block %d\n", inode->s5_direct_blocks[i]);
                        s5_free_block(fs, inode->s5_direct_blocks[i]);

                        s5_dirty_inode(fs, inode);
                        inode->s5_direct_blocks[i] = 0;
                }
        }

        if (((S5_TYPE_DATA == inode->s5_type)
             || (S5_TYPE_DIR == inode->s5_type))
            && inode->s5_indirect_block) {
                pframe_t *ibp;
                uint32_t *b;

                pframe_get(S5FS_TO_VMOBJ(fs),
                           (unsigned)inode->s5_indirect_block,
                           &ibp);
                KASSERT(ibp
                        && "because never fails for block_device "
                        "vm_objects");
                pframe_pin(ibp);

                b = (uint32_t *)(ibp->pf_addr);
                for (i = 0; i < S5_NIDIRECT_BLOCKS; ++i) {
                        KASSERT(b[i] != inode->s5_indirect_block);
                        if (b[i])
                                s5_free_block(fs, b[i]);
                }

                pframe_unpin(ibp);

                s5_free_block(fs, inode->s5_indirect_block);
        }

        inode->s5_indirect_block = 0;
        inode->s5_type = S5_TYPE_FREE;
        s5_dirty_inode(fs, inode);

        lock_s5(fs);
        inode->s5_next_free = fs->s5f_super->s5s_free_inode;
        fs->s5f_super->s5s_free_inode = inode->s5_number;
        unlock_s5(fs);

        s5_dirty_inode(fs, inode);
        s5_dirty_super(fs);
}

/*
 * Locate the directory entry in the given inode with the given name,
 * and return its inode number. If there is no entry with the given
 * name, return -ENOENT.
 *
 * You'll probably want to use s5_read_file and name_match
 *
 * You can either read one dirent at a time or optimize and read more.
 * Either is fine.
 */
int
s5_find_dirent(vnode_t *vnode, const char *name, size_t namelen)
{
    KASSERT(vnode != NULL && name != NULL);

    off_t seek = 0;
    s5_dirent_t dirents[NDIRENTS]; // read 5 dirents at one time to speed up

    while(seek < vnode->vn_len) {
        int read_res = s5_read_file(vnode, seek, (char*) dirents, NDIRENTS * sizeof(s5_dirent_t));

        if(read_res < 0) {
            return read_res;
        }

        uint32_t i;
        for(i = 0;i < (read_res / sizeof(s5_dirent_t));++i) {
            if(name_match(dirents[i].s5d_name, name, namelen)) {
                return dirents[i].s5d_inode;
            }
        }
        seek += read_res;
    }
    return -ENOENT;
}

/*
 * Locate the directory entry in the given inode with the given name,
 * and delete it. If there is no entry with the given name, return
 * -ENOENT.
 *
 * In order to ensure that the directory entries are contiguous in the
 * directory file, you will need to move the last directory entry into
 * the remove dirent's place.
 *
 * When this function returns, the inode refcount on the removed file
 * should be decremented.
 *
 * It would be a nice (but optional!) extension to free blocks from the end of
 * the directory file which are no longer needed.
 *
 * Don't forget to dirty appropriate blocks!
 *
 * You probably want to use vget(), vput(), s5_read_file(),
 * s5_write_file(), and s5_dirty_inode().
 */
int
s5_remove_dirent(vnode_t *vnode, const char *name, size_t namelen)
{
    KASSERT(vnode != NULL && vnode->vn_ops->mkdir != NULL);

    off_t seek = 0;
    s5_dirent_t dirents[NDIRENTS]; // read 5 dirents at one time to speed up

    off_t offset = -1;
    int ino = -1;
    while(seek < vnode->vn_len) {
        int read_res = s5_read_file(vnode, seek, (char*) dirents, NDIRENTS * sizeof(s5_dirent_t));

        if(read_res < 0) {
            return read_res;
        }

        uint32_t i;
        for(i = 0;i < (read_res / sizeof(s5_dirent_t));++i) {
            if(name_match(dirents[i].s5d_name, name, namelen)) {
                offset = seek + i *  sizeof(s5_dirent_t);
                ino = dirents[i].s5d_inode;
                break;
            }
        }
        seek += read_res;
    }

    if(offset == -1) {
        return -ENOENT;
    }

    /* if the dirent to remove is not the last dirent, we need to
     * copy the last dirent into its place */
    if((unsigned) vnode->vn_len > offset + sizeof(s5_dirent_t)){
        s5_dirent_t to_move;

        int read_res = s5_read_file(vnode, vnode->vn_len - sizeof(s5_dirent_t), 
                                    (char*) &to_move, sizeof(s5_dirent_t));

        if(read_res < 0) return read_res;

        int write_res = s5_write_file(vnode, offset, (char*) &to_move, sizeof(s5_dirent_t));

        if(write_res < 0) return write_res;
    }

    s5fs_t *fs = VNODE_TO_S5FS(vnode);

    s5_inode_t *dir_inode = VNODE_TO_S5INODE(vnode);

    /* decrease the length of the dir, and mark it as dirty */
    vnode->vn_len -= sizeof(s5_dirent_t);
    dir_inode->s5_size -= sizeof(s5_dirent_t);
    s5_dirty_inode(fs, dir_inode);

    /* decrement the linkcount on the unlinked file */
    vnode_t *deleted_vnode = vget(fs->s5f_fs, ino);
    s5_inode_t *deleted_inode = VNODE_TO_S5INODE(deleted_vnode);

    deleted_inode->s5_linkcount--;

    s5_dirty_inode(fs, deleted_inode);

    vput(deleted_vnode);

    return 0;
}

/*
 * Create a new directory entry in directory 'parent' with the given name, which
 * refers to the same file as 'child'.
 *
 * When this function returns, the inode refcount on the file that was linked to
 * should be incremented.
 *
 * Remember to incrament the ref counts appropriately
 *
 * You probably want to use s5_find_dirent(), s5_write_file(), and s5_dirty_inode().
 */
int
s5_link(vnode_t *parent, vnode_t *child, const char *name, size_t namelen)
{
    KASSERT(parent != NULL && parent->vn_ops->mkdir != NULL);
    KASSERT(child != NULL);

    if(s5_find_dirent(parent, name, namelen) != -ENOENT) {
        dbg(DBG_S5FS, "the name is already exist.\n");
        return -EEXIST;
    }

    s5fs_t *fs = VNODE_TO_S5FS(parent);

    s5_inode_t *child_inode = VNODE_TO_S5INODE(child);
    s5_inode_t *parent_inode = VNODE_TO_S5INODE(parent);
    int ino = child_inode->s5_number;

    s5_dirent_t new_dirent;
    memcpy(new_dirent.s5d_name, name, namelen);
    new_dirent.s5d_name[namelen] = '\0';
    new_dirent.s5d_inode = ino;

    int write_res = s5_write_file(parent, parent->vn_len, (char*) &new_dirent, sizeof(new_dirent));
    if(write_res < 0)  return write_res;

    s5_dirty_inode(fs, parent_inode);

    /* increment the linkcount */
    if(parent != child) {
        child_inode->s5_linkcount++;
        s5_dirty_inode(fs, child_inode);
    }

    return 0;
}

/*
 * Return the number of blocks that this inode has allocated on disk.
 * This should include the indirect block, but not include sparse
 * blocks.
 *
 * This is only used by s5fs_stat().
 *
 * You'll probably want to use pframe_get().
 */
int
s5_inode_blocks(vnode_t *vnode)
{
    s5_inode_t *inode = VNODE_TO_S5INODE(vnode);

    int alloc_blocks = 0;

    int i;
    for(i = 0;i < S5_NDIRECT_BLOCKS;++i) {
        if(inode->s5_direct_blocks[i] != 0) {
            alloc_blocks++;
        }
    }

    /* if we have indirect blocks */
    if(inode->s5_indirect_block != 0) {
        alloc_blocks++; // include the indirect block

        pframe_t *pageframe;
        mmobj_t *mmobj = S5FS_TO_VMOBJ(VNODE_TO_S5FS(vnode));
        int get_res = pframe_get(mmobj, inode->s5_indirect_block, &pageframe);

        if(get_res < 0) return get_res;

        int j;
        for(j = 0;j < S5_NDIRECT_BLOCKS;++j) {
            if(((int*)pageframe->pf_addr)[j] != 0){
                alloc_blocks++;
            }
        }
    }
    return alloc_blocks;
}

