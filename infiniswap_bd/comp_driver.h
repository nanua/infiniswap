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

#ifndef IS_COMP_DRIVER_H
#define IS_COMP_DRIVER_H

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/lzo.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/cpumask.h>
#include <linux/nodemask.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/blk-mq.h>
#include <linux/mutex.h>

#include "comp_pool.h"
#include "infiniswap.h"

#define MIN(a, b) ((a < b) ? a : b)

struct IS_comp_hq_private {
	unsigned int index;  // index of the hardware queue
	unsigned int queue_depth;
	struct IS_comp_driver *driver;  // pointer to the compression layer driver
	void *buffer;  // buffer for transferring data

	void *cmem;  // buffer for storing compressed data
	void *compress_workmem;  // compression working memory for LZO, LZ4, ...
	struct mutex lock;  // lock for protecting cmem, compress_workmem, and buffer
	struct IS_queue *is_q;
};

struct IS_comp_driver {
	struct zbud_pool *pool;
	struct workqueue_struct *req_workqueue;
	struct IS_comp_hq_private *hw_queue_private;
	struct IS_file *is_file;
};

struct IS_comp_work {
	struct blk_mq_hw_ctx *hctx;
	struct request *req;
	struct work_struct work;
};

int IS_queue_rq(struct blk_mq_hw_ctx *hctx, struct request *req);

#endif //IS_COMP_DRIVER_H
