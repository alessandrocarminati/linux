/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TODO: comment
 */

#include <kunit/test.h>

struct mem_test_ctx {
	char *kmem;
	char __user *umem;
	size_t size;
};

static int mem_test_init(struct kunit *test)
{
	unsigned long user_addr;
	struct mem_test_ctx *ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, ctx);
	test->priv = ctx;
	ctx->size = PAGE_SIZE * 4;
	ctx->kmem = kunit_kmalloc(test, ctx->size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx->kmem);

	user_addr = kunit_vm_mmap(test, NULL, 0, ctx->size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0);
	KUNIT_ASSERT_NE_MSG(test, user_addr, 0, "Could not create userspace mm");
	KUNIT_ASSERT_LT_MSG(test, user_addr, (unsigned long)TASK_SIZE, "Failed to allocate user memory");
	ctx->umem = (char __user *)user_addr;
	return 0;
}

static void read_mem_invalid_offset_test(struct kunit *test)
{
	struct file fake_file = { };
	struct mem_test_ctx *ctx = test->priv;
	loff_t pos = -1;
	ssize_t ret;

	ret = read_mem(&fake_file, ctx->umem, PAGE_SIZE / 2, &pos);

	KUNIT_EXPECT_EQ(test, ret, -EFAULT);
}

static void read_mem_valid_basic_test(struct kunit *test)
{
	struct file fake_file = { };
	struct mem_test_ctx *ctx = test->priv;
	loff_t pos = 0;
	ssize_t ret;

	ret = read_mem(&fake_file, ctx->umem, PAGE_SIZE / 2, &pos);

	KUNIT_EXPECT_GE(test, ret, 0);
}


static struct kunit_case mem_cases[] = {
	KUNIT_CASE_PARAM(read_mem_invalid_offset_test, NULL),
	KUNIT_CASE_PARAM(read_mem_valid_basic_test, NULL),
	{}
};

static struct kunit_suite mem_suite = {
	.name = "devmem-read_mem",
	.init = mem_test_init,
	.test_cases = mem_cases,
};

kunit_test_suite(mem_suite);
