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

#include "infiniswap.h"
#include "comp_driver.h"

static inline int valid_io_request(struct request *req)
{
	u64 start, end, bound;

	/* unaligned request */
	if (unlikely(blk_rq_pos(req) & (IS_SECT_NUM_PER_PAGE - 1)))
		return 0;
	if (unlikely(blk_rq_bytes(req) & (PAGE_SIZE - 1)))
		return 0;

	start = blk_rq_pos(req);
	end = start + (blk_rq_bytes(req) >> IS_SECT_SHIFT);
	bound = IS_SECT_NUM;
	/* out of range range */
	if (unlikely(start >= bound || end > bound || start > end))
		return 0;

	/* I/O request is valid */
	return 1;
}

static void update_position(u32 *index, int *offset, struct bio_vec *bvec)
{
	if (*offset + bvec->bv_len >= PAGE_SIZE)
		(*index)++;
	*offset = (*offset + bvec->bv_len) % PAGE_SIZE;
}

static int IS_comp_read_page(struct IS_comp_driver *driver, unsigned int page_index,
                             void *buffer, void *cmem, struct IS_queue *is_q)
{
	int ret;
	ret = zbud_read(driver->pool, buffer, cmem, page_index, is_q);
	if (ret < 0) {
		pr_err("%s, error in zbud_read, page_index: %d\n",
		       __func__, page_index);
		return ret;
	}

	return 0;
}

static int IS_comp_write_page(struct IS_comp_driver *driver, unsigned int page_index,
                              void *buffer, void *cmem, void *compress_workmem,
                              struct IS_queue *is_q)
{
	int ret;
	ret = zbud_write(driver->pool, buffer, cmem, compress_workmem, page_index, is_q);
	if (ret < 0) {
		pr_err("%s, error in zbud_write, page_index: %d\n",
		       __func__, page_index);
		return ret;
	}

	return 0;
}

static int IS_comp_bvec_rw(struct IS_comp_driver *driver, struct bio_vec *bvec,
                           void *buffer, int inpage_offset, int rw)
{
	struct page *page;
	void *page_addr;
	int ret;

	page = bvec->bv_page;
	page_addr = kmap_atomic(page);
	if (!page_addr) {
		pr_err("%s, fail to kmap, inpage_offset: %d, rw: %d\n",
		       __func__, inpage_offset, rw);
		ret = -ENOMEM;
		goto out;
	}
	switch (rw) {
	case READ:
		memcpy(page_addr + bvec->bv_offset,
		       buffer + inpage_offset,
		       bvec->bv_len);
		break;
	case WRITE:
		memcpy(buffer + inpage_offset,
		       page_addr + bvec->bv_offset, bvec->bv_len);
		break;
	}
	kunmap_atomic(page_addr);
	return 0;

out:
	return ret;
}

static int IS_comp_request_fn(struct request *req, struct IS_comp_hq_private *private)
{
	struct IS_comp_driver *driver;
	struct bio_vec *raw_bvec, bvec;
	struct req_iterator req_iter;
	int rw, ret;
	unsigned int page_index, page_num, page_iter;
	int inpage_offset;
	int max_transfer_size;
	void *buffer, *cmem, *compress_workmem;
	struct IS_queue *is_q;

	driver = private->driver;
	is_q = private->is_q;

	if (!valid_io_request(req)) {
		pr_err("%s, request invalid, rw: %d, rq_pos: %ld, rq_bytes: %d\n",
		       __func__, rq_data_dir(req), blk_rq_pos(req), blk_rq_bytes(req));
		ret = -EINVAL;
		goto out;
	}

	rw = rq_data_dir(req);
	page_index = blk_rq_pos(req) >> IS_SECT_PER_PAGE_SHIFT;
	page_num = blk_rq_bytes(req) >> PAGE_SHIFT;
	buffer = private->buffer;
	cmem = private->cmem;
	compress_workmem = private->compress_workmem;

	page_iter = page_index;
	inpage_offset = 0;

	rq_for_each_segment (raw_bvec, req, req_iter) {
		if (rw == READ && inpage_offset == 0) {
			ret = IS_comp_read_page(driver, page_iter, buffer, cmem, is_q);
			if (ret < 0) {
				pr_err("%s, fail in IS_comp_read_page, page_index: %d, page_num: %d, page_iter: %d, err_code: %d\n",
				       __func__, page_index, page_num, page_iter, ret);
				goto out;
			}
		}

		max_transfer_size = PAGE_SIZE - inpage_offset;
		bvec.bv_page = raw_bvec->bv_page;
		bvec.bv_len = MIN(max_transfer_size, raw_bvec->bv_len);
		bvec.bv_offset = raw_bvec->bv_offset;

		ret = IS_comp_bvec_rw(driver, &bvec, buffer, inpage_offset, rw);
		if (ret < 0) {
			pr_err("%s, fail in IS_comp_bvec_rw, "
			       "page_index: %d, page_num: %d, page_iter: %d, inpage_offset: %d, "
			       "bvec.bv_len: %d, bvec.bv_offset: %d, rw: %d, err_code: %d\n",
			       __func__, page_index, page_num, page_iter, inpage_offset, bvec.bv_len, bvec.bv_offset, rw, ret);
			goto out;
		}

		if (rw == WRITE && raw_bvec->bv_len >= max_transfer_size) {
			ret = IS_comp_write_page(driver, page_iter, buffer, cmem, compress_workmem, is_q);
			if (ret < 0) {
				pr_err("%s, fail in IS_comp_write_page, "
				       "page_index: %d, page_num: %d, page_iter: %d, err_code: %d\n",
				       __func__, page_index, page_num, page_iter, ret);
				goto out;
			}
		}

		if (rw == READ && raw_bvec->bv_len > max_transfer_size) {
			ret = IS_comp_read_page(driver, page_iter + 1, buffer, cmem, is_q);
			if (ret < 0) {
				pr_err("%s, fail in IS_comp_read_page, "
				       "page_index: %d, page_num: %d, page_iter: %d, err_code: %d\n",
				       __func__, page_index, page_num, page_iter + 1, ret);
				goto out;
			}
		}

		if (raw_bvec->bv_len > max_transfer_size) {
			bvec.bv_len = raw_bvec->bv_len - max_transfer_size;
			bvec.bv_offset = raw_bvec->bv_offset + max_transfer_size;

			ret = IS_comp_bvec_rw(driver, &bvec, buffer, 0, rw);
			if (ret < 0) {
				pr_err("%s, fail in IS_comp_bvec_rw, "
				       "page_index: %d, page_num: %d, page_iter: %d, inpage_offset: %d, "
				       "bvec.bv_len: %d, bvec.bv_offset: %d, rw: %d, err_code: %d\n",
				       __func__, page_index, page_num, page_iter + 1, 0, bvec.bv_len, bvec.bv_offset, rw, ret);
				goto out;
			}
		}

		update_position(&page_iter, &inpage_offset, raw_bvec);
	}
	return 0;

out:
	return ret;
}

static void IS_comp_io_fn(struct work_struct *work)
{
	struct IS_comp_work *cur_work;
	struct blk_mq_hw_ctx *hctx;
	struct request *req;
	struct IS_comp_hq_private *private;
	unsigned int page_index, page_num;
	int ret;

	cur_work = container_of(work, struct IS_comp_work, work);
	hctx = cur_work->hctx;
	req = cur_work->req;
	kfree(cur_work);

	private = hctx->driver_data;
	mutex_lock(&private->lock);
	ret = IS_comp_request_fn(req, private);
	if (ret < 0) {
		page_index = blk_rq_pos(req) >> IS_SECT_PER_PAGE_SHIFT;
		page_num = blk_rq_bytes(req) >> PAGE_SHIFT;

		pr_err("%s, fail in IS_comp_request_fn, "
		       "page_index: %d, page_num: %d\n",
		       __func__, page_index, page_num);
		goto out;
	}

	mutex_unlock(&private->lock);
	blk_mq_end_io(req, 0);
	return;

out:
	mutex_unlock(&private->lock);
	req->errors = ret;
	blk_mq_end_io(req, req->errors);
	return;
}

#ifdef COMP_ENABLE
int IS_queue_rq(struct blk_mq_hw_ctx *hctx, struct request *req)
{
	struct IS_comp_work *cur_work;
	struct IS_comp_hq_private *private;
	unsigned int page_index, page_num;
	int ret;

	page_index = blk_rq_pos(req) >> IS_SECT_PER_PAGE_SHIFT;
	page_num = blk_rq_bytes(req) >> PAGE_SHIFT;
	private = hctx->driver_data;

	cur_work = kmalloc(sizeof(struct IS_comp_work), GFP_NOIO);
	if (!cur_work) {
		pr_err("%s, unable to allocate work struct, "
		       "page_index: %d, page_num: %d\n",
		       __func__, page_index, page_num);
		ret = -ENOMEM;
		goto out;
	}
	cur_work->hctx = hctx;
	cur_work->req = req;
	INIT_WORK(&cur_work->work, IS_comp_io_fn);
	if (!queue_work(private->driver->req_workqueue, &cur_work->work)) {
		pr_err("%s, work is already on the queue, "
		       "page_index: %d, page_num: %d\n",
		       __func__, page_index, page_num);
		ret = -EINVAL;
		goto free_work;
	}
	return BLK_MQ_RQ_QUEUE_OK;

free_work:
	kfree(cur_work);
out:
	req->errors = ret;
	blk_mq_end_io(req, req->errors);
	return BLK_MQ_RQ_QUEUE_ERROR;
}
#endif
