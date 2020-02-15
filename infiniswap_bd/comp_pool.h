/*
 * Compression layer over Infiniswap
 * Copyright (C) 2020, Hongyi Wang, Yuhong Zhong, Columbia University
 *
 * zbud.c
 * Copyright (C) 2013, Seth Jennings, IBM
 * Concepts based on zcache internal zbud allocator by Dan Magenheimer.
 *
 * zram, Compressed RAM block device
 * Copyright (C) 2008, 2009, 2010  Nitin Gupta
 * This code is released using a dual license strategy: BSD/GPL
 * You can choose the licence that better fits your requirements.
 * Released under the terms of 3-clause BSD License
 * Released under the terms of GNU General Public License Version 2.0
 * Project home: http://compcache.googlecode.com
 */

#ifndef IS_COMP_POOL_H
#define IS_COMP_POOL_H

#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/preempt.h>
#include <linux/slab.h>
#include <linux/lzo.h>
#include <linux/lz4.h>
#include <linux/mutex.h>

#include "infiniswap.h"

/*****************
 * Structures
*****************/

enum buddy { FIRST, LAST };

struct zbud_header {
	struct list_head list;  // used for unbud list
	struct mutex lock;
	unsigned int first_chunks;
	unsigned int last_chunks;
	struct ipage *ipage;
};

struct zbud_info_entry {
	unsigned long flags;  // valid, compressed, ...(unused)...
	union {
		struct {
			struct zbud_header *zhdr;
			enum buddy buddy;
			size_t clen;
		};  // compressed page
		struct ipage *ipage;  // direct page
	};
	struct mutex lock;
};

#define ENTRY_VALID     0
#define ENTRY_COMPRESSED    1

// ipage represents page within infiniswap
struct ipage {
	struct list_head list;  // used for ipage free list
	unsigned long ipage_index;
};

struct zbud_stat {
	/* historical stats */
	atomic_t num_comp_0_pages;  // [0, 0.25 * PAGE_SIZE)
	atomic_t num_comp_1_pages;  // [0.25 * PAGE_SIZE, 0.5 * PAGE_SIZE)
	atomic_t num_comp_2_pages;  // [0.5 * PAGE_SIZE, 0.75 * PAGE_SIZE)
	atomic_t num_comp_3_pages;  // [0.75 * PAGE_SIZE, PAGE_SIZE]
	atomic_t num_is_read_fail;
	atomic_t num_is_write_fail;
	atomic_t num_malloc_fail;
	atomic_t num_ialloc_fail;
	atomic_t num_compress_fail;
	atomic_t num_compress_inflation;
	atomic_t num_decompress_fail;
	atomic_t num_read;
	atomic_t num_write;
	atomic_t num_invalid_read;

	/* reflective stats */
	atomic_t num_direct_pages;
	atomic_t num_unbuddied_pages;
	atomic_t num_buddy;
	atomic_t num_free_ipage;
};

struct zbud_pool {
	struct zbud_stat stat;
	struct list_head unbuddied[IS_COMP_CHUNK_NUM_PER_PAGE];  // unbud list
	struct mutex unbud_lock;  // lock for unbud list
	struct list_head free_ipage;  // ipage free list
	struct mutex ipage_lock;  // lock for ipage free list
	struct zbud_info_entry zbud_info_table[IS_PAGE_NUM];  // lookup table
};

/*****************
 * Prototypes
*****************/

struct zbud_pool *zbud_create_pool(void);
void zbud_destroy_pool(struct zbud_pool *pool);
int zbud_write(struct zbud_pool *pool, void *umem, void *cmem, void *compress_workmem,
		unsigned long rqst_page_index, struct IS_queue *is_q);
int zbud_read(struct zbud_pool *pool, void *buffer, void *cmem, unsigned long rqst_page_index,
		struct IS_queue *is_q);
void zbud_reset_stat(struct zbud_pool *pool);
int zbud_force_clear_all(struct zbud_pool *pool);

#endif //IS_COMP_POOL_H
