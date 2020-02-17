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

#include "comp_pool.h"
/*****************
 * Helpers
*****************/

/* Converts an allocation size in bytes to size in zbud chunks */
static int size_to_chunks(int size)
{
	return (size + IS_COMP_CHUNK_SIZE - 1) >> IS_COMP_CHUNK_SHIFT;
}

#define for_each_unbuddied_list(_iter, _begin)  \
        for ((_iter) = (_begin); (_iter) < IS_COMP_CHUNK_NUM_PER_PAGE; (_iter)++)

static struct ipage *atomic_get_ipage(struct zbud_pool *pool)
{
	struct ipage *ipage;
	mutex_lock(&pool->ipage_lock);
	if (list_empty(&pool->free_ipage)) {
		ipage = NULL;
		goto unlock;
	}
	ipage = list_first_entry(&pool->free_ipage, struct ipage, list);
	list_del(&ipage->list);

unlock:
	mutex_unlock(&pool->ipage_lock);
	return ipage;
}

static void atomic_put_ipage(struct zbud_pool *pool, struct ipage *ipage)
{
	mutex_lock(&pool->ipage_lock);
	list_add(&ipage->list, &pool->free_ipage);
	mutex_unlock(&pool->ipage_lock);
}

/*
 * Delete the zbud header from the unbud list
 */
static void atomic_del_zhdr(struct zbud_pool *pool, struct zbud_header *zhdr)
{
	mutex_lock(&pool->unbud_lock);
	list_del(&zhdr->list);
	mutex_unlock(&pool->unbud_lock);
}

/*
 * Put the zbud header into the unbud list
 */
static void atomic_put_zhdr(struct zbud_pool *pool, struct zbud_header *zhdr)
{
	int free_chunks;

	free_chunks = IS_COMP_CHUNK_NUM_PER_PAGE - zhdr->first_chunks -
	              zhdr->last_chunks;
	mutex_lock(&pool->unbud_lock);
	list_add(&zhdr->list, &pool->unbuddied[free_chunks]);
	mutex_unlock(&pool->unbud_lock);
}

/*
 * Get a suitable (i.e., with large enough free space) unbud page from the unbud list
 */
static struct zbud_header *atomic_get_zhdr(struct zbud_pool *pool, int free_chunks_lb)
{
	struct zbud_header *zhdr = NULL;
	int i, retry;

	do {
		retry = 0;
		mutex_lock(&pool->unbud_lock);
		for_each_unbuddied_list(i, free_chunks_lb)
		{
			if (!list_empty(&pool->unbuddied[i])) {
				zhdr = list_first_entry(&pool->unbuddied[i],
				                        struct zbud_header,
				                        list);
				if (mutex_trylock(&zhdr->lock)) {
					break;
				} else {
					/*
					 * retry if a suitable unbud page is found
					 * but is currently protected by its lock
					 */
					zhdr = NULL;
					retry = 1;
				}
			}
		}
		if (!zhdr) {
			/*
			 * need to release unbud_lock when fail to get an unbud page
			 * to eliminate dead-lock
			 */
			mutex_unlock(&pool->unbud_lock);
		}
	} while (!zhdr && retry);

	if (zhdr) {
		list_del(&zhdr->list);
		mutex_unlock(&pool->unbud_lock);
	}

	return zhdr;
}

/*
 * Write a direct page (page that cannot be compressed) to Infiniswap
 */
static int zbud_direct_write(struct zbud_pool *pool, void *umem, unsigned long rqst_page_index,
                             struct IS_queue *is_q)
{
	struct zbud_info_entry *entry;
	struct ipage *ipage;
	int ret;

	ipage = atomic_get_ipage(pool);
	if (!ipage) {
		pr_err("%s, fail to allocate new ipage, rqst_page_index: %ld\n",
		       __func__, rqst_page_index);

		atomic_inc(&pool->stat.num_ialloc_fail);
		ret = -ENOSPC;
		goto out;
	}

	ret = IS_write(ipage->ipage_index, umem, is_q, rqst_page_index);
	if (ret < 0) {
		pr_err("%s, fail to write to infiniswap, rqst_page_index: %ld, ipage_index: %ld\n",
		       __func__, rqst_page_index, ipage->ipage_index);

		atomic_inc(&pool->stat.num_is_write_fail);
		goto free_ipage;
	}

	entry = &pool->zbud_info_table[rqst_page_index];
	__set_bit(ENTRY_VALID, &entry->flags);
	__clear_bit(ENTRY_COMPRESSED, &entry->flags);
	entry->ipage = ipage;

	atomic_inc(&pool->stat.num_direct_pages);
	atomic_dec(&pool->stat.num_free_ipage);
	return 0;

free_ipage:
	atomic_put_ipage(pool, ipage);
out:
	return ret;
}

/*
 * Write a compressed page to Infiniswap to form a full buddy with an unbud page
 */
static int zbud_buddy_write(struct zbud_pool *pool, void *cmem, size_t clen,
                            unsigned long rqst_page_index, struct zbud_header *zhdr, int chunks,
                            enum buddy bud, struct IS_queue *is_q)
{
	struct zbud_info_entry *entry;
	struct ipage *ipage;
	unsigned long ipage_index;
	int ret;

	ipage = zhdr->ipage;
	ipage_index = ipage->ipage_index;

	ret = IS_write_sectors((ipage_index << (PAGE_SHIFT - IS_COMP_CHUNK_SHIFT)) +
	                        ((bud == FIRST) ? 0 : ((PAGE_SIZE >> IS_COMP_CHUNK_SHIFT) - chunks)),
	                       chunks << IS_COMP_CHUNK_SHIFT, cmem, is_q, rqst_page_index);
	if (ret < 0) {
		pr_err("%s, fail to write to infiniswap, rqst_page_index: %ld, ipage_index: %ld\n",
		       __func__, rqst_page_index, ipage_index);

		atomic_inc(&pool->stat.num_is_write_fail);
		goto out;
	}

	if (bud == FIRST)
		zhdr->first_chunks = chunks;
	else
		zhdr->last_chunks = chunks;
	entry = &pool->zbud_info_table[rqst_page_index];
	__set_bit(ENTRY_VALID, &entry->flags);
	__set_bit(ENTRY_COMPRESSED, &entry->flags);
	entry->zhdr = zhdr;
	entry->buddy = bud;
	entry->clen = clen;

	atomic_dec(&pool->stat.num_unbuddied_pages);
	atomic_inc(&pool->stat.num_buddy);

	return 0;

out:
	return ret;
}

/*
 * Write a compressed unbud page to Infiniswap
 */
static int zbud_unbud_write(struct zbud_pool *pool, void *cmem, size_t clen, int chunks,
                            unsigned long rqst_page_index, struct IS_queue *is_q)
{
	struct zbud_info_entry *entry;
	struct zbud_header *zhdr;
	struct ipage *ipage;
	unsigned long ipage_index;
	int ret;

	zhdr = kmalloc(sizeof(struct zbud_header), GFP_NOIO);
	if (!zhdr) {
		pr_err("%s, fail to allocate memory for zbud_header, rqst_page_index: %ld\n",
		       __func__, rqst_page_index);

		atomic_inc(&pool->stat.num_malloc_fail);
		ret = -ENOMEM;
		goto out;
	}
	ipage = atomic_get_ipage(pool);
	if (!ipage) {
		pr_err("%s, fail to allocate new ipage, rqst_page_index: %ld\n",
		       __func__, rqst_page_index);

		atomic_inc(&pool->stat.num_ialloc_fail);
		ret = -ENOSPC;
		goto free_zhdr;
	}
	ipage_index = ipage->ipage_index;

	ret = IS_write_sectors(ipage_index << (PAGE_SHIFT - IS_COMP_CHUNK_SHIFT),
	                       chunks << IS_COMP_CHUNK_SHIFT, cmem, is_q, rqst_page_index);
	if (ret < 0) {
		pr_err("%s, fail to write to infiniswap, rqst_page_index: %ld, ipage_index: %ld\n",
		       __func__, rqst_page_index, ipage_index);

		atomic_inc(&pool->stat.num_is_write_fail);
		goto free_ipage;
	}

	INIT_LIST_HEAD(&zhdr->list);
	mutex_init(&zhdr->lock);
	mutex_lock(&zhdr->lock);
	zhdr->first_chunks = chunks;
	zhdr->last_chunks = 0;
	zhdr->ipage = ipage;
	atomic_put_zhdr(pool, zhdr);

	entry = &pool->zbud_info_table[rqst_page_index];
	__set_bit(ENTRY_VALID, &entry->flags);
	__set_bit(ENTRY_COMPRESSED, &entry->flags);
	entry->zhdr = zhdr;
	entry->buddy = FIRST;
	entry->clen = clen;

	atomic_inc(&pool->stat.num_unbuddied_pages);
	atomic_dec(&pool->stat.num_free_ipage);
	return 0;

free_ipage:
	atomic_put_ipage(pool, ipage);
free_zhdr:
	kfree(zhdr);
out:
	return ret;
}

/*
 * Clear a direct page from Infiniswap
 */
static int zbud_direct_clear(struct zbud_pool *pool, unsigned long rqst_page_index)
{
	struct zbud_info_entry *entry;
	struct ipage *ipage;

	entry = &pool->zbud_info_table[rqst_page_index];
	ipage = entry->ipage;

	atomic_put_ipage(pool, ipage);
	__clear_bit(ENTRY_VALID, &entry->flags);

	atomic_dec(&pool->stat.num_direct_pages);
	atomic_inc(&pool->stat.num_free_ipage);
	return 0;
}

/*
 * Clear a compressed unbud page from Infiniswap
 */
static int zbud_unbud_clear(struct zbud_pool *pool, unsigned long rqst_page_index)
{
	struct zbud_info_entry *entry;
	struct zbud_header *zhdr;
	struct ipage *ipage;

	entry = &pool->zbud_info_table[rqst_page_index];
	zhdr = entry->zhdr;
	ipage = zhdr->ipage;

	__clear_bit(ENTRY_VALID, &entry->flags);
	atomic_put_ipage(pool, ipage);
	atomic_del_zhdr(pool, zhdr);
	mutex_unlock(&zhdr->lock);
	kfree(zhdr);

	atomic_dec(&pool->stat.num_unbuddied_pages);
	atomic_inc(&pool->stat.num_free_ipage);
	return 0;
}

/*
 * Clear a compressed buddied page from Infiniswap
 */
static int zbud_buddy_clear(struct zbud_pool *pool, unsigned long rqst_page_index)
{
	struct zbud_info_entry *entry;
	struct zbud_header *zhdr;
	enum buddy bud;

	entry = &pool->zbud_info_table[rqst_page_index];
	zhdr = entry->zhdr;
	bud = entry->buddy;

	if (bud == FIRST)
		zhdr->first_chunks = 0;
	else
		zhdr->last_chunks = 0;
	atomic_put_zhdr(pool, zhdr);
	mutex_unlock(&zhdr->lock);
	__clear_bit(ENTRY_VALID, &entry->flags);

	atomic_dec(&pool->stat.num_buddy);
	atomic_inc(&pool->stat.num_unbuddied_pages);
	return 0;
}

static int zbud_clear(struct zbud_pool *pool, unsigned long rqst_page_index)
{
	struct zbud_info_entry *entry;
	struct zbud_header *zhdr;
	int ret;

	entry = &pool->zbud_info_table[rqst_page_index];

	if (!test_bit(ENTRY_VALID, &entry->flags))
		return 0;
	if (!test_bit(ENTRY_COMPRESSED, &entry->flags)) {
		ret = zbud_direct_clear(pool, rqst_page_index);
		if (ret < 0) {
			pr_err("%s, fail in zbud_direct_clear, rqst_page_index: %ld\n",
       			       __func__, rqst_page_index);
			return ret;
		}
		return 0;
	}

	zhdr = entry->zhdr;
	if (zhdr->first_chunks == 0 || zhdr->last_chunks == 0) {
		ret = zbud_unbud_clear(pool, rqst_page_index);
		if (ret < 0) {
			pr_err("%s, fail in zbud_unbud_clear, rqst_page_index: %ld\n",
              		       __func__, rqst_page_index);
			return ret;
		}
	} else {
		ret = zbud_buddy_clear(pool, rqst_page_index);
		if (ret < 0) {
			pr_err("%s, fail in zbud_buddy_clear, rqst_page_index: %ld\n",
              		       __func__, rqst_page_index);
			return ret;
		}
	}
	return 0;
}

/*
 * Read a direct page (page that cannot be compressed) from Infiniswap
 */
static int zbud_direct_read(struct zbud_pool *pool, unsigned long rqst_page_index,
                            void *buffer, struct IS_queue *is_q)
{
	struct zbud_info_entry *entry;
	struct ipage *ipage;
	unsigned long ipage_index;
	int ret;

	entry = &pool->zbud_info_table[rqst_page_index];
	ipage = entry->ipage;
	ipage_index = ipage->ipage_index;
	ret = IS_read(ipage_index, buffer, is_q, rqst_page_index);
	if (ret < 0) {
		pr_err("%s, fail to read from infiniswap, rqst_page_index: %ld, ipage_index: %ld\n",
		       __func__, rqst_page_index, ipage_index);
		atomic_inc(&pool->stat.num_is_read_fail);
		goto out;
	}
	return 0;

out:
	return ret;
}

/*
 * Read a compressed page from Infiniswap
 */
static int zbud_comp_read(struct zbud_pool *pool, unsigned long rqst_page_index,
                           void *buffer, struct IS_queue *is_q)
{
	struct zbud_info_entry *entry;
	struct zbud_header *zhdr;
	enum buddy bud;
	size_t clen;
	struct ipage *ipage;
	unsigned long ipage_index;
	int ret;

	entry = &pool->zbud_info_table[rqst_page_index];
	zhdr = entry->zhdr;
	bud = entry->buddy;
	clen = entry->clen;
	ipage = zhdr->ipage;
	ipage_index = ipage->ipage_index;

	ret = IS_read_sectors((ipage_index << (PAGE_SHIFT - IS_COMP_CHUNK_SHIFT))
	                      + ((bud == FIRST) ? 0 : ((PAGE_SIZE >> IS_COMP_CHUNK_SHIFT)
	                                               - zhdr->last_chunks)),
	                      ((bud == FIRST) ? zhdr->first_chunks : zhdr->last_chunks)
	                      << IS_COMP_CHUNK_SHIFT,
	                      buffer, is_q, rqst_page_index);
	if (ret < 0) {
		pr_err("%s, fail to read from infiniswap, rqst_page_index: %ld, ipage_index: %ld\n",
		       __func__, rqst_page_index, ipage_index);
		atomic_inc(&pool->stat.num_is_read_fail);
		goto out;
	}
	return 0;

out:
	return ret;
}

/*****************
 * API Functions
*****************/

struct zbud_pool *zbud_create_pool(void)
{
	struct zbud_pool *pool;
	int i;
	struct ipage *ipage;
	struct list_head *pos, *n;

	pool = vmalloc(sizeof(struct zbud_pool));
	if (!pool)
		goto out;

	mutex_init(&pool->ipage_lock);
	mutex_init(&pool->unbud_lock);

	for_each_unbuddied_list(i, 0) INIT_LIST_HEAD(&pool->unbuddied[i]);

	INIT_LIST_HEAD(&pool->free_ipage);
	for (i = 0; i < IS_PAGE_NUM; ++i) {
		ipage = kmalloc(sizeof(struct ipage), GFP_KERNEL);
		if (!ipage)
			goto free_ipage;
		ipage->ipage_index = i;
		INIT_LIST_HEAD(&ipage->list);
		list_add_tail(&ipage->list, &pool->free_ipage);
	}

	memset(pool->zbud_info_table, 0, sizeof(pool->zbud_info_table));
	for (i = 0; i < IS_PAGE_NUM; ++i)
		mutex_init(&pool->zbud_info_table[i].lock);

	atomic_set(&pool->stat.num_comp_0_pages, 0);
	atomic_set(&pool->stat.num_comp_1_pages, 0);
	atomic_set(&pool->stat.num_comp_2_pages, 0);
	atomic_set(&pool->stat.num_comp_3_pages, 0);
	atomic_set(&pool->stat.num_is_read_fail, 0);
	atomic_set(&pool->stat.num_is_write_fail, 0);
	atomic_set(&pool->stat.num_malloc_fail, 0);
	atomic_set(&pool->stat.num_ialloc_fail, 0);
	atomic_set(&pool->stat.num_compress_fail, 0);
	atomic_set(&pool->stat.num_compress_inflation, 0);
	atomic_set(&pool->stat.num_decompress_fail, 0);
	atomic_set(&pool->stat.num_read, 0);
	atomic_set(&pool->stat.num_write, 0);
	atomic_set(&pool->stat.num_invalid_read, 0);
	atomic_set(&pool->stat.num_direct_pages, 0);
	atomic_set(&pool->stat.num_unbuddied_pages, 0);
	atomic_set(&pool->stat.num_buddy, 0);
	atomic_set(&pool->stat.num_free_ipage, IS_PAGE_NUM);

	return pool;

free_ipage:
	list_for_each_safe (pos, n, &pool->free_ipage) {
		ipage = list_entry(pos, struct ipage, list);
		kfree(ipage);
	};
	vfree(pool);
out:
	return NULL;
}

void zbud_destroy_pool(struct zbud_pool *pool)
{
	struct list_head *pos, *n;
	struct ipage *ipage;

	zbud_force_clear_all(pool);
	list_for_each_safe (pos, n, &pool->free_ipage) {
		ipage = list_entry(pos, struct ipage, list);
		kfree(ipage);
	};
	vfree(pool);
}

int zbud_write(struct zbud_pool *pool, void *umem, void *cmem,
               void *compress_workmem, unsigned long rqst_page_index, struct IS_queue *is_q)
{
	int chunks, ret;
	struct zbud_info_entry *entry;
	struct zbud_header *zhdr;
	enum buddy bud;

	int comp_ret;
	size_t clen;

	atomic_inc(&pool->stat.num_write);
	entry = &pool->zbud_info_table[rqst_page_index];
	mutex_lock(&entry->lock);
	if (test_bit(ENTRY_COMPRESSED, &entry->flags)) {
		zhdr = entry->zhdr;
		mutex_lock(&zhdr->lock);
	}

	/* cleanup existing entry */
	ret = zbud_clear(pool, rqst_page_index);
	if (ret < 0) {
		pr_err("%s, fail to clear the existing entry, rqst_page_index: %ld, ret: %d\n",
       		       __func__, rqst_page_index, ret);
		goto unlock;
	}

	/* compress */
#ifdef COMP_LZ4
	comp_ret = lz4_compress(umem, PAGE_SIZE, cmem, &clen, compress_workmem);
#else
	comp_ret = lzo1x_1_compress(umem, PAGE_SIZE, cmem, &clen, compress_workmem);
#endif
	if (comp_ret != 0) {
		pr_err("%s, fail to compress, rqst_page_index: %ld, comp_ret: %d\n",
              	       __func__, rqst_page_index, comp_ret);
		atomic_inc(&pool->stat.num_compress_fail);
		ret = -EINVAL;
		goto unlock;
	}

	chunks = size_to_chunks(clen);
	if ((chunks << IS_COMP_CHUNK_SHIFT) >= PAGE_SIZE) {
		atomic_inc(&pool->stat.num_compress_inflation);
		ret = zbud_direct_write(pool, umem, rqst_page_index, is_q);
		if (ret < 0) {
			pr_err("%s, fail to direct write, rqst_page_index: %ld, ret: %d\n",
	              	       __func__, rqst_page_index, ret);
			goto unlock;
		} else {
			ret = 0;
			goto unlock;
		}
	}

	if (clen < IS_COMP_0_UB)
		atomic_inc(&pool->stat.num_comp_0_pages);
	else if (clen < IS_COMP_1_UB)
		atomic_inc(&pool->stat.num_comp_1_pages);
	else if (clen < IS_COMP_2_UB)
		atomic_inc(&pool->stat.num_comp_2_pages);
	else
		atomic_inc(&pool->stat.num_comp_3_pages);

	/* First, try to find an unbuddied page */
	zhdr = atomic_get_zhdr(pool, chunks);
	if (zhdr) {
		/* successfully find an unbuddied page */
		if (zhdr->first_chunks == 0)
			bud = FIRST;
		else
			bud = LAST;
		ret = zbud_buddy_write(pool, cmem, clen, rqst_page_index, zhdr,
		                       chunks, bud, is_q);
		if (ret < 0) {
			pr_err("%s, fail to buddy write, rqst_page_index: %ld, ret: %d\n",
	              	       __func__, rqst_page_index, ret);
			goto put_zhdr;
		} else {
			ret = 0;
			goto unlock;
		}
	}

	/* Couldn't find unbuddied page, create new one */
	ret = zbud_unbud_write(pool, cmem, clen, chunks, rqst_page_index, is_q);
	if (ret < 0) {
		pr_err("%s, fail to unbud write, rqst_page_index: %ld, ret: %d\n",
		       __func__, rqst_page_index, ret);
		goto unlock;
	} else {
		ret = 0;
		goto unlock;
	}

put_zhdr:
	atomic_put_zhdr(pool, zhdr);
	mutex_unlock(&zhdr->lock);
unlock:
	mutex_unlock(&entry->lock);
	if (test_bit(ENTRY_COMPRESSED, &entry->flags)) {
		zhdr = entry->zhdr;
		mutex_unlock(&zhdr->lock);
	}
	return ret;
}

int zbud_read(struct zbud_pool *pool, void *buffer, void *cmem,
              unsigned long rqst_page_index, struct IS_queue *is_q)
{
	struct zbud_info_entry *entry;
	struct zbud_header *zhdr;
	int ret;

	int comp_ret;
	size_t clen, dlen;

	atomic_inc(&pool->stat.num_read);
	entry = &pool->zbud_info_table[rqst_page_index];
	mutex_lock(&entry->lock);
	if (test_bit(ENTRY_COMPRESSED, &entry->flags)) {
		zhdr = entry->zhdr;
		mutex_lock(&zhdr->lock);
	}

	if (!test_bit(ENTRY_VALID, &entry->flags)) {
		atomic_inc(&pool->stat.num_invalid_read);
		ret = 0;
		goto unlock;
	}

	if (!test_bit(ENTRY_COMPRESSED, &entry->flags)) {
		/* request page is not compressed */
		ret = zbud_direct_read(pool, rqst_page_index, buffer, is_q);
		if (ret < 0)
			pr_err("%s, fail to direct read, rqst_page_index: %ld, ret: %d\n",
			       __func__, rqst_page_index, ret);
		goto unlock;
	}

	/* request page is compressed */
	zhdr = entry->zhdr;
	clen = entry->clen;
	ret = zbud_comp_read(pool, rqst_page_index, cmem, is_q);
	if (ret < 0) {
		pr_err("%s, fail to buddy read, rqst_page_index: %ld, ret: %d\n",
		       __func__, rqst_page_index, ret);
		goto unlock;
	}

	/* decompress */
	dlen = PAGE_SIZE;
#ifdef COMP_LZ4
	comp_ret = lz4_decompress(cmem, &clen, buffer, dlen);
#else
	comp_ret = lzo1x_decompress_safe(cmem, clen, buffer, &dlen);
#endif
	if (comp_ret != 0 || dlen != PAGE_SIZE) {
		pr_err("%s, fail to decompress, rqst_page_index: %ld, comp_ret: %d\n",
                       __func__, rqst_page_index, comp_ret);
		atomic_inc(&pool->stat.num_decompress_fail);
		ret = -EINVAL;
		goto unlock;
	}

	mutex_unlock(&entry->lock);
	if (test_bit(ENTRY_COMPRESSED, &entry->flags)) {
		zhdr = entry->zhdr;
		mutex_unlock(&zhdr->lock);
	}
	return 0;

unlock:
	mutex_unlock(&entry->lock);
	if (test_bit(ENTRY_COMPRESSED, &entry->flags)) {
		zhdr = entry->zhdr;
		mutex_unlock(&zhdr->lock);
	}
	return ret;
}

void zbud_reset_stat(struct zbud_pool *pool)
{
	atomic_set(&pool->stat.num_comp_0_pages, 0);
	atomic_set(&pool->stat.num_comp_1_pages, 0);
	atomic_set(&pool->stat.num_comp_2_pages, 0);
	atomic_set(&pool->stat.num_comp_3_pages, 0);
	atomic_set(&pool->stat.num_is_read_fail, 0);
	atomic_set(&pool->stat.num_is_write_fail, 0);
	atomic_set(&pool->stat.num_malloc_fail, 0);
	atomic_set(&pool->stat.num_ialloc_fail, 0);
	atomic_set(&pool->stat.num_compress_fail, 0);
	atomic_set(&pool->stat.num_compress_inflation, 0);
	atomic_set(&pool->stat.num_decompress_fail, 0);
	atomic_set(&pool->stat.num_read, 0);
	atomic_set(&pool->stat.num_write, 0);
	atomic_set(&pool->stat.num_invalid_read, 0);
	/* will not change reflective stats */
}

int zbud_force_clear_all(struct zbud_pool *pool)
{
	unsigned long rqst_page_index;
	int ret;

	for (rqst_page_index = 0; rqst_page_index < IS_PAGE_NUM; ++rqst_page_index) {
		ret = zbud_clear(pool, rqst_page_index);
		if (ret < 0) {
			pr_err("%s, fail to force clear, rqst_page_index: %ld, ret: %d\n",
			       __func__, rqst_page_index, ret);
			return ret;
		}
	}
	return 0;
}
