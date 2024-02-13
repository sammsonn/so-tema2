#define METADATA_SIZE		(sizeof(struct block_meta))
#define MMAP_THRESHOLD	(128 * 1024)
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))

#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
