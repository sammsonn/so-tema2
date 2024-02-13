// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"

#include "block_meta.h"
#include "symbols.h"

struct block_meta *global_first, *global_last;

void block_coalesce(void)
{
	struct block_meta *block = global_first;

	while (block && block->next) {
		if (block->status == STATUS_FREE && block->next->status == STATUS_FREE) {
			if (block->next == global_last)
				global_last = block;

			block->size = block->size + block->next->size + METADATA_SIZE;
			block->next = block->next->next;
		} else {
			block = block->next;
		}
	}
}

struct block_meta *block_expand(struct block_meta *block, size_t size)
{
	while (block && block->next) {
		if (block->next->status == STATUS_FREE) {
			if (block->next == global_last)
				global_last = block;

			block->size += block->next->size + METADATA_SIZE;
			block->next = block->next->next;
		} else {
			return block;
		}
		if (block->size >= ALIGN(size))
			return block;
	}

	return block;
}

struct block_meta *find_free_block(size_t size)
{
	struct block_meta *block = global_first;
	struct block_meta *freeBlock = NULL;
	size_t minSize = 999999;

	while (block) {
		if (block->status == STATUS_FREE && block->size < minSize && block->size >= size) {
			minSize = block->size;
			freeBlock = block;
		}

		block = block->next;
	}

	return freeBlock;
}

void block_split(struct block_meta *block, size_t size)
{
	struct block_meta *newBlock = (struct block_meta *)((void *)block + METADATA_SIZE + ALIGN(size));

	if (newBlock != block->next) {
		newBlock->size = block->size - ALIGN(size) - METADATA_SIZE;
		newBlock->status = STATUS_FREE;
		newBlock->next = block->next;
		newBlock->prev = block;

		block->size = ALIGN(size);
		block->next = newBlock;

		if (block == global_last)
			global_last = newBlock;
	}
}

struct block_meta *brk_allocate(size_t size)
{
	if (!global_first) {
		struct block_meta *block = sbrk(MMAP_THRESHOLD);

		DIE(block == MAP_FAILED, "Error at malloc sbrk preallocate\n");

		block->size = MMAP_THRESHOLD - METADATA_SIZE;
		block->status = STATUS_ALLOC;
		block->prev = NULL;
		block->next = NULL;

		global_first = block;
		global_last = block;

		return block + 1;
	}
	block_coalesce();
	struct block_meta *freeBlock = find_free_block(size);

	if (freeBlock) {
		if (ALIGN(size) + METADATA_SIZE + ALIGN(1) <= freeBlock->size)
			block_split(freeBlock, size);

		freeBlock->status = STATUS_ALLOC;

		return freeBlock + 1;
	}

	if (global_last->status == STATUS_FREE) {
		size_t newSize = ALIGN(size) - global_last->size;

		void *ret = sbrk(newSize);

		DIE(ret == MAP_FAILED, "Error at malloc sbrk last block expansion\n");

		global_last->size = ALIGN(size);
		global_last->status = STATUS_ALLOC;

		return global_last + 1;
	}

	size_t totalSize = ALIGN(size) + METADATA_SIZE;

	struct block_meta *block = sbrk(totalSize);

	DIE(block == MAP_FAILED, "Error at malloc sbrk allocate\n");

	block->size = ALIGN(size);
	block->status = STATUS_ALLOC;
	block->prev = global_last;
	block->next = NULL;
	global_last->next = block;

	global_last = block;

	return block + 1;
}

struct block_meta *mmap_allocate(size_t size)
{
	size_t totalSize = ALIGN(size) + METADATA_SIZE;

	struct block_meta *block = mmap(NULL, totalSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	DIE(block == MAP_FAILED, "Error at malloc mapping\n");

	block->size = ALIGN(size);
	block->status = STATUS_MAPPED;
	block->prev = NULL;
	block->next = NULL;

	return block + 1;
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */

	if (size == 0)
		return NULL;
	else if (ALIGN(size) + METADATA_SIZE < MMAP_THRESHOLD)
		return brk_allocate(size);
	else
		return mmap_allocate(size);
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */

	if (!ptr)
		return;

	struct block_meta *block = (struct block_meta *)ptr - 1;

	if (block->status == STATUS_ALLOC) {
		block->status = STATUS_FREE;

		return;
	} else if (block->status == STATUS_MAPPED) {
		int ret = munmap(block, block->size + METADATA_SIZE);

		DIE(ret == -1, "Error at free unmapping\n");

		return;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */

	size_t totalSize = nmemb * size;
	struct block_meta *ptr;

	if (totalSize == 0)
		return NULL;
	else if (ALIGN(totalSize) + METADATA_SIZE < (unsigned long)getpagesize())
		ptr = brk_allocate(totalSize);
	else
		ptr = mmap_allocate(totalSize);

	memset(ptr, 0, totalSize);

	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */

	if (ptr == NULL)
		return os_malloc(size);

	struct block_meta *block = (struct block_meta *)ptr - 1;

	if (block->status == STATUS_FREE)
		return NULL;

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	if (block->status == STATUS_MAPPED || (ALIGN(size) + METADATA_SIZE >= MMAP_THRESHOLD)) {
		struct block_meta *newBlock = os_malloc(size);

		memcpy(newBlock, ptr, size < block->size ? size : block->size);
		os_free(ptr);

		return newBlock;
	}

	if (ALIGN(size) > block->size) {
		if (block == global_last) {
			size_t newSize = ALIGN(size) - block->size;

			void *ret = sbrk(newSize);

			DIE(ret == MAP_FAILED, "Error at realloc sbrk last block expansion\n");

			block->size = ALIGN(size);
			block->status = STATUS_ALLOC;

			return block + 1;
		} else if (block->next->status == STATUS_FREE &&
				   ALIGN(size) <= (block->size + METADATA_SIZE + block->next->size)) {
			block = block_expand(block, size);
			block_split(block, size);

			return block + 1;
		}

		block_coalesce();
		struct block_meta *freeBlock = find_free_block(size);

		if (freeBlock) {
			if (freeBlock + 1 != ptr) {
				memcpy(freeBlock + 1, ptr, block->size);
				os_free(ptr);
			}

			freeBlock->status = STATUS_ALLOC;
			block_split(freeBlock, size);

			return freeBlock + 1;
		}

		struct block_meta *newBlock = os_malloc(size);

		memcpy(newBlock, ptr, block->size);
		os_free(ptr);

		return newBlock;
	}

	if (block->next && (ALIGN(size) + METADATA_SIZE + ALIGN(1) <= block->size))
		block_split(block, size);

	return block + 1;
}
