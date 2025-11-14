/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025 Red Hat inc
 */

#ifndef _LINUX_CHAR_MEM_H
#define _LINUX_CHAR_MEM_H

#if IS_ENABLED(CONFIG_KUNIT)
static ssize_t read_mem(struct file *file, char __user *buf,
			size_t count, loff_t *ppos);
static ssize_t write_mem(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos);
#endif

#endif /* _LINUX_CHAR_MEM_H */
