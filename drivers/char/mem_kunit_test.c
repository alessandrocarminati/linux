/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TODO: comment
 */

#include <kunit/test.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <asm-generic/io.h>

#include "mem.h"

struct mem_test_ctx {
	char *kmem;
	char __user *umem;
	size_t size;
};

#if defined(CONFIG_X86) && defined(CONFIG_STRICT_DEVMEM)
static const char *mem_test_plan = "x86-strict";
#elif defined(CONFIG_X86)
static const char *mem_test_plan = "x86-nonstrict";
#elif defined(CONFIG_STRICT_DEVMEM)
#else
static const char *mem_test_plan = "generic";
#endif

static void kunit_hexdump_page(struct kunit *test, const void *addr)
{
	const u8 *p = addr;
	size_t offset = 0;

	for (offset = 0; offset < PAGE_SIZE; offset += 16) {
		char line[80];
		int pos = 0;
		int i;

		pos += scnprintf(line + pos, sizeof(line) - pos,
				 "%08zx: ", offset);

		for (i = 0; i < 16; i++) {
			pos += scnprintf(line + pos, sizeof(line) - pos,
					 "%02x ", p[offset + i]);
		}

		pos += scnprintf(line + pos, sizeof(line) - pos, " |");

		for (i = 0; i < 16; i++) {
			u8 c = p[offset + i];
			pos += scnprintf(line + pos, sizeof(line) - pos,
					 "%c", ((c>31) && (c<127)) ? c : '.');
		}

		pos += scnprintf(line + pos, sizeof(line) - pos, "|");

		kunit_info(test, "%s\n", line);
	}
}

static void kunit_hexdump_compare_page(struct kunit *test,
                                       const void *a,
                                       const void *b)
{
	const u8 *pa = a;
	const u8 *pb = b;
	size_t offset;

	for (offset = 0; offset < PAGE_SIZE; offset += 16) {
		char line[160];
		int pos = 0;
		int i;

		pos += scnprintf(line + pos, sizeof(line) - pos,
				 "%08zx: ", offset);

		for (i = 0; i < 16; i++)
			pos += scnprintf(line + pos, sizeof(line) - pos,
					 "%02x ", pa[offset + i]);

		pos += scnprintf(line + pos, sizeof(line) - pos, " | ");

		for (i = 0; i < 16; i++)
			pos += scnprintf(line + pos, sizeof(line) - pos,
					 "%02x ", pb[offset + i]);

		kunit_info(test, "%s\n", line);
	}
}

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
	kunit_info(test, "Selected devmem read_mem test plan: %s\n", mem_test_plan);
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

static void read_mem_read_1M_le_at_0(struct kunit *test)
{
	struct file fake_file = { };
	struct mem_test_ctx *ctx = test->priv;
	phys_addr_t pa = 0;
	loff_t pos = pa;
	void *direct;
	int ret;

	direct = phys_to_virt(pa);

	ret = read_mem(&fake_file, ctx->umem, PAGE_SIZE / 2, &pos);

	KUNIT_ASSERT_EQ(test, ret, PAGE_SIZE / 2);

//	kunit_hexdump_page(test, ctx->umem);
//	kunit_hexdump_compare_page(test, ctx->umem, direct);
	KUNIT_EXPECT_MEMEQ(test, ctx->umem, direct, PAGE_SIZE / 2);
}

static void read_mem_read_1M_le_at_ram(struct kunit *test)
{
	struct file fake_file = { };
	struct mem_test_ctx *ctx = test->priv;
	phys_addr_t pa = 0x20000;
	loff_t pos = pa;
	void *direct;
	int ret;

	direct = phys_to_virt(pa);

	memset(direct, 0xaa, PAGE_SIZE / 2);

	ret = read_mem(&fake_file, ctx->umem, PAGE_SIZE / 2, &pos);

//	kunit_hexdump_compare_page(test, ctx->umem, direct);
	KUNIT_ASSERT_EQ(test, ret, PAGE_SIZE / 2);

#if defined(CONFIG_X86) && defined(CONFIG_STRICT_DEVMEM)
	kunit_info(test, "Expect different\n");
	KUNIT_EXPECT_MEMNEQ(test, ctx->umem, direct, PAGE_SIZE / 2);
#else
	kunit_info(test, "Expect equal\n");
	KUNIT_EXPECT_MEMEQ(test, ctx->umem, direct, PAGE_SIZE / 2);
#endif
}

static void read_mem_less_page(struct kunit *test)
{
	struct file fake_file = { };
	struct mem_test_ctx *ctx = test->priv;
	char *buf = kunit_kmalloc(test, PAGE_SIZE, GFP_KERNEL);
	phys_addr_t pa = virt_to_phys(buf);
	loff_t pos = pa;
	int ret;

	memset(buf, 0xaa, PAGE_SIZE / 2);

	ret = read_mem(&fake_file, ctx->umem, PAGE_SIZE / 2, &pos);

#if defined(CONFIG_STRICT_DEVMEM)
	kunit_info(test, "expected error\n");
	KUNIT_ASSERT_EQ(test, ret, -EPERM);
#else
	kunit_info(test, "expected read\n");
	KUNIT_ASSERT_EQ(test, ret, PAGE_SIZE / 2);
	KUNIT_EXPECT_MEMEQ(test, ctx->umem, buf, PAGE_SIZE / 2);
#endif
}

static void read_mem_2_pages(struct kunit *test)
{
	struct file fake_file = { };
	struct mem_test_ctx *ctx = test->priv;
	char *buf = kunit_kmalloc(test, 2 * PAGE_SIZE, GFP_KERNEL);
	phys_addr_t pa = virt_to_phys(buf);
	loff_t pos = pa;
	int ret;

	memset(buf, 0xaa, PAGE_SIZE);
	memset(buf + PAGE_SIZE, 0xbb, PAGE_SIZE);

	ret = read_mem(&fake_file, ctx->umem, 2 * PAGE_SIZE, &pos);
	kunit_info(test, "read_mem read %d\n", ret);

#if defined(CONFIG_STRICT_DEVMEM)
	kunit_info(test, "expected error\n");
	KUNIT_ASSERT_EQ(test, ret, -EPERM);
#else
	kunit_info(test, "expected read\n");
	KUNIT_ASSERT_EQ(test, ret, 2 * PAGE_SIZE);

	KUNIT_EXPECT_MEMEQ(test, ctx->umem, buf, 2 * PAGE_SIZE);
#endif
}

static struct kunit_case mem_cases[] = {
	KUNIT_CASE_PARAM(read_mem_invalid_offset_test, NULL),
	KUNIT_CASE_PARAM(read_mem_valid_basic_test, NULL),
	KUNIT_CASE_PARAM(read_mem_read_1M_le_at_0, NULL),
	KUNIT_CASE_PARAM(read_mem_read_1M_le_at_ram, NULL),
	KUNIT_CASE_PARAM(read_mem_less_page, NULL),
	KUNIT_CASE_PARAM(read_mem_2_pages, NULL),
	{}
};

static struct kunit_suite mem_suite = {
	.name = "devmem-read_mem",
	.init = mem_test_init,
	.test_cases = mem_cases,
};

kunit_test_suite(mem_suite);
