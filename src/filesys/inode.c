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
#define DEBUG_INODE

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
    disk_sector_t blocks[14];           /* blocks */
    disk_sector_t block_count;
    disk_sector_t indirect_count;
    disk_sector_t dindirect_count;

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
    off_t offset = pos / DISK_SECTOR_SIZE;

    /* direct inode 내에서 읽을 수 있는 경우 */
    if(offset < INODE_DIRECT_BLOCKS)
    {
      result = disk_inode->blocks[offset];
    }
    /* indirect inode 내에서 읽을 수 있는 경우 */
    else if(offset < INODE_DIRECT_BLOCKS + PTR_PER_BLOCKS)
    {
      disk_read(filesys_disk, disk_inode->blocks[13], &blocks);
      offset -= INODE_DIRECT_BLOCKS;
      result = blocks[offset];

    } else {
      /* double indirect inode 내에서 읽을 수 있는 경우 */

      //1st level table read
      disk_read(filesys_disk, disk_inode->blocks[14], &blocks);
      offset -= (INODE_DIRECT_BLOCKS + PTR_PER_BLOCKS);

      //2nd level table read
      disk_read(filesys_disk, blocks[offset / PTR_PER_BLOCKS], &blocks);  //???Q???
      offset %= PTR_PER_BLOCKS;
      result = blocks[offset];

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


bool
inode_allocate(struct inode *inode, off_t length)
{
  size_t new_sectors = bytes_to_sectors(length) - bytes_to_sectors(inode->length);
  static char zeros[DISK_SECTOR_SIZE];

  if(new_sectors == 0)
  {
    inode->length = length;
    return true;
  }

  /* direct inode alloc */
  disk_sector_t sector_count = inode->block_count;
  disk_sector_t indirect_count = inode->indirect_count;
  disk_sector_t dindirect_count = inode->dindirect_count;

  while (sector_count < INODE_DIRECT_BLOCKS && new_sectors != 0)
  {
    free_map_allocate(1, &inode->blocks[sector_count]);
    cache_write(inode->blocks[sector_count], zeros, 0, DISK_SECTOR_SIZE);
    sector_count++;
    new_sectors--;
  }

  /* indirect inode alloc */
  if (sector_count < INODE_DIRECT_BLOCKS + INODE_INDIRECT_BLOCKS && new_sectors != 0)
  {
    disk_sector_t indirect_block[PTR_PER_BLOCKS];

    // indirect block table 읽어오기
    if (inode->indirect_count == 0)
      free_map_allocate (1, &inode->blocks[sector_count]); // maybe sector_count == 12
    else
      cache_read(inode->blocks[sector_count], &indirect_block, 0, PTR_PER_BLOCKS); // ???Q???

    while (indirect_count < PTR_PER_BLOCKS && new_sectors != 0)
    {
      free_map_allocate(1, &indirect_block[indirect_count]);
      cache_write(indirect_block[indirect_count], zeros, 0, DISK_SECTOR_SIZE);
      indirect_count++;
      new_sectors--;
    }

    /* cache_write가 필요해... ???Q??? */
    cache_write(inode->blocks[sector_count], indirect_block, indirect_count, DISK_SECTOR_SIZE);
    if (indirect_count == PTR_PER_BLOCKS) 
    {
      indirect_count = 0;
      sector_count++;
    }

  }

  /* Double inode alloc */
  if (sector_count == 13 && new_sectors != 0)
  {
    disk_sector_t fst_btable[PTR_PER_BLOCKS];
    disk_sector_t snd_btable[PTR_PER_BLOCKS];

    if (indirect_count == 0 && dindirect_count == 0)
      free_map_allocate(1, &inode->blocks[sector_count]);
    else
      cache_read(inode->blocks[sector_count], &fst_btable, 0, PTR_PER_BLOCKS);

    while (indirect_count < PTR_PER_BLOCKS && new_sectors != 0)
    {

      if(dindirect_count == 0 && new_sectors != 0)
        free_map_allocate(1, &fst_btable[indirect_count]);
      else
        cache_read(fst_btable[indirect_count], &snd_btable, 0, PTR_PER_BLOCKS);

      while (dindirect_count < PTR_PER_BLOCKS && new_sectors != 0)
      {
        free_map_allocate(1, &snd_btable[dindirect_count]);
        cache_write(snd_btable[dindirect_count], zeros, 0, DISK_SECTOR_SIZE);
        dindirect_count++;
        new_sectors--;
      }

      cache_write(fst_btable[indirect_count], zeros, 0, DISK_SECTOR_SIZE);
      if(dindirect_count == PTR_PER_BLOCKS)
      {
        dindirect_count = 0;
        indirect_count++;
      }

    }

    /* cache_write가 필요해... ???Q??? */
    cache_write(inode->blocks[sector_count], fst_btable, indirect_count, DISK_SECTOR_SIZE);

  }

  inode->length = length;
  inode->block_count = sector_count;
  inode->indirect_count = indirect_count;
  inode->dindirect_count = dindirect_count;

  return true;


}


/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   disk. -> make those sector be cached.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length)
{
#ifdef DEBUG_INODE
  printf("inode_create(): 진입\n");
#endif
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
      disk_inode->block_count = 0;
      disk_inode->magic = INODE_MAGIC;
      struct inode *inode = inode_open(sector);
      cache_write (sector, disk_inode, 0, DISK_SECTOR_SIZE);
      if(inode_allocate(inode, disk_inode->length))
      {
        disk_inode->block_count = inode->block_count;
        disk_inode->indirect_count = inode->indirect_count;
        disk_inode->dindirect_count = inode->dindirect_count;
        memcpy(&disk_inode->blocks, &inode->blocks, 14 * sizeof(disk_sector_t));
        //cache_write (sector, disk_inode, 0, DISK_SECTOR_SIZE);
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
#ifdef DEBUG_INODE
  printf("inode_open(): 진입\n");
#endif
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
  inode->length = 0;
  inode->block_count = 0;
  inode->indirect_count = 0;
  inode->dindirect_count = 0;
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

  //if(offset >= inode->length) return bytes_read;

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

  if (offset + size > inode->length) inode_allocate(inode, offset + size);

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
