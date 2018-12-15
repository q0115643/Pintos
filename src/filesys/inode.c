#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"
#include "devices/disk.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

//#define DEBUG

/* PJ4 : inode 구조체 변경 */
#define INODE_DIRECT_BLOCKS 12
#define INODE_INDIRECT_BLOCKS 1
#define INODE_DOUBLE_INDIRECT_BLOCKS 1
#define PTR_PER_BLOCKS 128


/* On-disk inode.
   Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    disk_sector_t start;                /* First data sector. */      // 4
    off_t length;                       /* File size in bytes. */     // 4
    unsigned magic;                     /* Magic number. */           // 4
    uint32_t unused[108];               /* Not used. */               // 125*4 = 500

    /* PJ4 */
    // 128 - 20 = 108
    disk_sector_t blocks[14];
    disk_sector_t block_count;
    disk_sector_t indirect_count;
    disk_sector_t dindirect_count;

  };

/* PJ4 : indirect inode for finding pointer */
struct inode_indirect_disk
{
  disk_sector_t ptr[14];
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}


/* In-memory inode. */
struct inode 
{
  struct list_elem elem;              /* Element in inode list. */
  disk_sector_t sector;               /* Sector number of disk location. */
  int open_cnt;                       /* Number of openers. */
  bool removed;                       /* True if deleted, false otherwise. */
  int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */


  off_t length;
  disk_sector_t blocks[14];
  size_t block_count;
  size_t indirect_count;
  size_t dindirect_count;

};


/* Returns the disk sector that contains byte offset POS within
   INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static disk_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  disk_sector_t result = -1;
  disk_sector_t blocks[PTR_PER_BLOCKS]; // for read from indirect inode blocks.

  struct inode_disk *disk_inode = (struct inode_disk *) malloc(DISK_SECTOR_SIZE);
  cache_read(inode_get_inumber(inode), disk_inode, 0, DISK_SECTOR_SIZE);

  if(pos < disk_inode->length)
  {
    //result = disk_inode->start + pos / DISK_SECTOR_SIZE;
    /* direct inode 내에서 읽을 수 있는 경우 */
    if(pos < DISK_SECTOR_SIZE * INODE_DIRECT_BLOCKS)
    {
      result = disk_inode->blocks[pos / DISK_SECTOR_SIZE];
    }
    /* indirect inode 내에서 읽을 수 있는 경우 */
    else if(pos < DISK_SECTOR_SIZE * (INODE_DIRECT_BLOCKS + PTR_PER_BLOCKS * INODE_INDIRECT_BLOCKS))
    {
      // cache read해도 될 것 같은디
      disk_read(filesys_disk, disk_inode->blocks[13], &blocks);
      pos -= DISK_SECTOR_SIZE * INODE_DIRECT_BLOCKS;
      pos %= DISK_SECTOR_SIZE * PTR_PER_BLOCKS;
      result = blocks[pos / DISK_SECTOR_SIZE];

    } else {
      /* double indirect inode 내에서 읽을 수 있는 경우 */
      disk_read(filesys_disk, disk_inode->blocks[14], &blocks);
      pos -= DISK_SECTOR_SIZE * INODE_DIRECT_BLOCKS;
      size_t index = pos / (DISK_SECTOR_SIZE * PTR_PER_BLOCKS);
      disk_read(filesys_disk, blocks[index], &blocks);
      pos -= DISK_SECTOR_SIZE * PTR_PER_BLOCKS;
      pos %= DISK_SECTOR_SIZE * PTR_PER_BLOCKS;
      result = blocks[pos / DISK_SECTOR_SIZE];

    }

  }

  free(disk_inode);
  return result;
}



/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}



/* PJ4 inode할당에 대해 extend 가능하게.. */
bool
inode_alloc(struct inode_disk * disk_inode)
{
  /* length에 맞게.. */
  struct inode inode;
  inode.length = 0;
  inode.block_count = 0;
  inode.indirect_count = 0;
  inode.dindirect_count = 0;

  inode_alloc_extend(inode, disk_inode->length);
  disk_inode->block_count = inode.block_count;
  disk_inode->indirect_count = inode.indirect_count;
  disk_inode->dindirect_count = inode.dindirect_count;
  memcpy(&disk_inode->blocks, &inode.blocks, PTR_PER_BLOCKS * sizeof(disk_sector_t));
  return true;

}

void
inode_alloc_extend(struct inode *inode, off_t length)
{
  size_t new_sectors = bytes_to_sectors(length) - bytes_to_sectors(inode->length);
  static char zeros[DISK_SECTOR_SIZE];

  if (new_sectors == 0) 
  {
    inode->length = length;
    return;
  }

  // dircet inode allocation
  while (inode->block_count < INODE_DIRECT_BLOCKS && new_sectors != 0)
  {
    free_map_allocate (1, &inode->blocks[inode->block_count]);
    //cache write
    cache_write(inode->blocks[inode->block_count], zeros, 0, DISK_SECTOR_SIZE);

    inode->block_count++;
    new_sectors--;
  }

  // indirect inode allocation
  if (inode->block_count < INODE_DIRECT_BLOCKS + INODE_INDIRECT_BLOCKS && new_sectors != 0)
  {
    disk_sector_t block[PTR_PER_BLOCKS];
    if(inode->indirect_count == 0)
      free_map_allocate (1, &inode->blocks[inode->block_count]);
    else
      //cache에서 읽어와야 한다.
      cache_read(inode->blocks[inode->block_count], &block, 0, PTR_PER_BLOCKS * sizeof(disk_sector_t));

    while (inode->indirect_count < PTR_PER_BLOCKS && new_sectors != 0)
    {
      free_map_allocate (1, &inode->blocks[inode->indirect_count]);

      // cache write
      cache_write(inode->blocks[inode->indirect_count], zeros, 0, DISK_SECTOR_SIZE);

      inode->indirect_count++;
      new_sectors--;
    }

    //cache write
    cache_write(inode->blocks[inode->block_count], zeros, 0, DISK_SECTOR_SIZE);

    if (inode->indirect_count == PTR_PER_BLOCKS)
    {
      inode->indirect_count = 0;
      inode->block_count++;
    }

  }

  // double indirect allocation
  if (inode->block_count < INODE_DIRECT_BLOCKS + INODE_INDIRECT_BLOCKS + INODE_DOUBLE_INDIRECT_BLOCKS 
    && new_sectors != 0)
  {
    disk_sector_t fst_btable[PTR_PER_BLOCKS];
    disk_sector_t snd_btable[PTR_PER_BLOCKS];

    // 첫번째 level block table read
    if (inode->dindirect_count == 0 && inode->indirect_count == 0)
      free_map_allocate(1, &inode->blocks[inode->block_count]);
    else
      //cahce에서 level one 읽어야 함
      cache_read(inode->blocks[inode->block_count], &fst_btable, 0, PTR_PER_BLOCKS * sizeof(disk_sector_t));

    while (inode->indirect_count < PTR_PER_BLOCKS && new_sectors != 0)
    {
      if (inode->dindirect_count == 0)
        free_map_allocate(1, &fst_btable[inode->indirect_count]);
      else
        //cache read
        cache_read(inode->blocks[inode->indirect_count], &snd_btable, 0, PTR_PER_BLOCKS * sizeof(disk_sector_t));

      while(inode->dindirect_count < PTR_PER_BLOCKS && new_sectors != 0)
      {
        free_map_allocate(1, &snd_btable[inode->dindirect_count]);

        //cache write
        cache_write(inode->blocks[inode->dindirect_count], zeros, 0, DISK_SECTOR_SIZE);

        inode->dindirect_count++;
        new_sectors--;
      }

      // cache write
      cache_write(inode->blocks[inode->indirect_count], zeros, 0, DISK_SECTOR_SIZE);

      if (inode->dindirect_count == PTR_PER_BLOCKS)
      {
        inode->dindirect_count = 0;
        inode->indirect_count++;
      }

    }

    // cache write
    cache_write(inode->blocks[inode->block_count], zeros, 0, DISK_SECTOR_SIZE);

  }

  inode->length = length;
  return;


}


/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   disk. -> make those sector be cached.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      //size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      if(inode_alloc(disk_inode))
      {
        cache_write(sector, disk_inode, 0, DISK_SECTOR_SIZE);
        success = true;
      }

      /*
      if (free_map_allocate (sectors, &disk_inode->start))
        {
          cache_write(sector, disk_inode, 0, DISK_SECTOR_SIZE);
          //disk_write (filesys_disk, sector, disk_inode);
          if (sectors > 0) 
            {
              static char zeros[DISK_SECTOR_SIZE];
              size_t i;
              
              for (i = 0; i < sectors; i++) 
                cache_write(disk_inode->start + i, zeros, 0, DISK_SECTOR_SIZE);
                //disk_write (filesys_disk, disk_inode->start + i, zeros); 
            }
          success = true; 
        } */
      free (disk_inode);
    }
  return success;
}



/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) 
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode_get_inumber(inode) == sector) 
        {
          inode_reopen(inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;
  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
  {
    struct inode_disk *disk_inode = (struct inode_disk *) malloc(DISK_SECTOR_SIZE);
    /* Remove from inode list and release lock. */
    list_remove (&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) 
    {
      cache_read(inode_get_inumber(inode), disk_inode, 0, DISK_SECTOR_SIZE);
      free_map_release(inode->sector, 1);
      free_map_release(disk_inode->start, bytes_to_sectors(disk_inode->length)); 
    }
    free(inode);
    free(disk_inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  if(offset >= inode->length) return bytes_read;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      cache_read(sector_idx, buffer + bytes_read, sector_ofs, chunk_size);
      if(sector_idx + 1 < disk_size(filesys_disk)) cache_read_ahead(sector_idx + 1);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
#ifdef DEBUG
  printf("inode_write_at(): 진입\n");
#endif
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  if (offset + size > inode->length) inode_alloc_extend(inode, offset + size);

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      cache_write(sector_idx, buffer + bytes_written, sector_ofs, chunk_size);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;

    }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  off_t length;
  struct inode_disk *disk_inode = (struct inode_disk *) malloc(DISK_SECTOR_SIZE);
  cache_read(inode_get_inumber(inode), disk_inode, 0, DISK_SECTOR_SIZE);
  length = disk_inode->length;
  free(disk_inode);
  return length;
}
