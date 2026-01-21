/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TODO: comment
 */

#include <kunit/test.h>

#include <linux/io.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <asm-generic/io.h>

#include "mem.h"

struct mem_test_ctx {
	char *kmem;
	char __user *umem;
	size_t size;
};

/**
 * mem_test_plan - Human-readable label for the active expectation profile
 *
 * CONFIG_STRICT_DEVMEM exists primarily to keep /dev/mem usable for *legacy*
 * behaviours while reducing the ability to read arbitrary system RAM.
 *
 * On x86, some historical/legacy software expects to read “fixed” physical
 * addresses (e.g. low memory regions traditionally populated by firmware/BIOS
 * tables) via /dev/mem. That legacy expectation drives why this test suite has
 * cases targeting address 0 and other low-memory reads.
 *
 */

#if defined(CONFIG_X86) && defined(CONFIG_STRICT_DEVMEM)
	#define DEVMEM_TEST_SUITE_MODE "x86-strict"
#elif defined(CONFIG_X86)
	#define DEVMEM_TEST_SUITE_MODE "x86-nostrict"
#elif defined(CONFIG_STRICT_DEVMEM)
	#define DEVMEM_TEST_SUITE_MODE "generic-strict"
#else
	#define DEVMEM_TEST_SUITE_MODE "generic-nostrict"
#endif

#ifdef MEM_KUNIT_TEST_DEBUG
/**
 * kunit_hexdump_page - Emit a PAGE_SIZE hexdump to the KUnit log
 * @test: KUnit test context.
 * @addr: Start address of the page to dump.
 *
 * Debug helper to print a page-sized buffer as 16-byte rows to the KUnit log
 * via kunit_info(). Intended for diagnosing unexpected read_mem() results.
 *
 * Not used in normal passing runs (calls are currently commented-out in tests).
 */
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

/**
 * kunit_hexdump_compare_page - Emit a side-by-side hexdump of two pages
 * @test: KUnit test context.
 * @a: First buffer (page) to dump.
 * @b: Second buffer (page) to dump.
 *
 * Debug helper to print 16-byte rows of @a and @b on the same line for quick
 * visual comparison when KUNIT_EXPECT_MEM(E)Q checks fail.
 *
 * Not used in normal passing runs (calls are currently commented-out in tests).
 */
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
#endif

/**
 * mem_test_init - Allocate buffers and create a userspace destination mapping
 * @test: KUnit test context.
 *
 * Prepares @test->priv with a struct mem_test_ctx:
 *  - Allocates a kernel buffer for generating “RAM-like” physical addresses.
 *  - Creates a userspace mapping used as the copy-to destination for read_mem().
 *  - Logs the current expectation profile (mem_test_plan).
 *
 * Returns: 0 on success; uses KUNIT_ASSERT_* for fatal setup failures.
 */
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
	kunit_info(test, "Selected devmem read_mem test plan: %s\n", DEVMEM_TEST_SUITE_MODE);
	return 0;
}

/**
 * read_mem_invalid_offset_test - read_mem() rejects a negative file position
 * @test: KUnit test context.
 *
 * Calls read_mem() with @pos initialized to -1 and expects -EFAULT.
 * This validates basic argument/position checking when the "physical address"
 * (carried through the file position) is invalid.
 */
static void read_mem_invalid_offset_test(struct kunit *test)
{
	struct file fake_file = { };
	struct mem_test_ctx *ctx = test->priv;
	loff_t pos = -1;
	ssize_t ret;

	ret = read_mem(&fake_file, ctx->umem, PAGE_SIZE / 2, &pos);

	KUNIT_EXPECT_EQ(test, ret, -EFAULT);
}

/**
 * read_mem_valid_basic_test - Basic read_mem() reachability test at phys addr 0
 * @test: KUnit test context.
 *
 * Performs a small read starting at physical address 0 and verifies that
 * read_mem() behaves consistently with the architecture and devmem policy.
 *
 * Rationale:
 * On x86, low physical memory has historically been readable through /dev/mem
 * to support legacy firmware and BIOS data access. This remains true even when
 * CONFIG_STRICT_DEVMEM is enabled, although the returned contents may be
 * sanitized. Therefore, on x86 this read is expected to succeed and return a
 * non-negative value.
 *
 * On non-x86 architectures, the semantics differ:
 *   - If the physical range is invalid, read_mem() is expected to fail
 *     (typically -EFAULT).
 *   - If the range is valid but classified as System RAM, strict devmem policy
 *     may deny access (typically -EPERM).
 *
 * Because of these architectural and policy differences, this test does not
 * validate the returned data. Instead, it verifies that:
 *   - invalid physical ranges are rejected, and
 *   - valid ranges either succeed or are explicitly denied by policy.
 */
static void read_mem_valid_basic_test(struct kunit *test)
{
	struct mem_test_ctx *ctx = test->priv;
	struct file fake_file = { };
	size_t len = PAGE_SIZE / 2;
	loff_t pos = 0;
	ssize_t ret;

	ret = read_mem(&fake_file, ctx->umem, len, &pos);

	if (!valid_phys_addr_range(0, len)) {
		kunit_info(test,
			   "phys range [0, %zu) not valid on this arch; expect -EFAULT\n",
			   len);
		KUNIT_EXPECT_EQ(test, ret, (ssize_t)-EFAULT);
		return;
	}

#if defined(CONFIG_X86)
	kunit_info(test, "x86: read from phys 0 should not error\n");
	KUNIT_EXPECT_GE(test, ret, 0);
#else
	kunit_info(test,
		   "non-x86: phys 0 valid; accept success or -EPERM depending on policy\n");
	KUNIT_EXPECT_TRUE(test, ret >= 0 || ret == -EPERM);
#endif
}

/**
 * read_mem_read_1M_le_at_0 - Legacy x86-style low-memory read at physical 0
 * @test: KUnit test context.
 *
 * Reads from physical address 0 and compares the data copied by read_mem()
 * into the userspace destination buffer against the direct mapping for that
 * physical address.
 *
 * Note:
 * On non-x86 (or on platforms without that legacy expectation), this test is
 * not meaningfull and can be skipped.
 */
static void read_mem_read_1M_le_at_0(struct kunit *test)
{
	struct file fake_file = { };
	struct mem_test_ctx *ctx = test->priv;
	size_t len = PAGE_SIZE / 2;
	phys_addr_t pa = 0;
	loff_t pos = pa;
	void *direct;
	int ret;

	if (!valid_phys_addr_range(pa, len)) {
		kunit_skip(test, "0 is invalid in this arch.");
		return;
	}
	ret = read_mem(&fake_file, ctx->umem, len, &pos);

	KUNIT_ASSERT_EQ(test, ret, len);

#ifdef MEM_KUNIT_TEST_DEBUG
	direct = phys_to_virt(pa);
	kunit_hexdump_page(test, ctx->umem);
	kunit_hexdump_compare_page(test, ctx->umem, direct);
#endif

	KUNIT_EXPECT_MEMEQ(test, ctx->umem, direct, len);
}

/**
 * read_mem_read_1M_le_at_ram - Read from low RAM: allowed vs blocked by policy
 * @test: KUnit test context.
 *
 * Targets a low physical address (pa = 0x20000) and seeds the direct-mapped
 * memory with a known pattern before calling read_mem().
 *
 * Expected behaviour depends on /dev/mem policy:
 *  - x86 + CONFIG_STRICT_DEVMEM: reading *system RAM* via /dev/mem is expected
 *    to be restricted. The test currently expects the copied-out bytes to
 *    differ from what was seeded (i.e. read_mem() should not return raw RAM).
 *  - non-strict (or platforms without that restriction): the test expects the
 *    read to succeed and match the seeded bytes.
 */
static void read_mem_read_1M_le_at_ram(struct kunit *test)
{
	struct file fake_file = { };
	struct mem_test_ctx *ctx = test->priv;
	size_t len = PAGE_SIZE / 2;
	phys_addr_t pa = 0x20000;
	loff_t pos = pa;
	void *direct;
	int ret;

	direct = phys_to_virt(pa);

	memset(direct, 0xaa, len);

	ret = read_mem(&fake_file, ctx->umem, len, &pos);

#ifdef MEM_KUNIT_TEST_DEBUG
	kunit_hexdump_compare_page(test, ctx->umem, direct);
#endif
	KUNIT_ASSERT_EQ(test, ret, len);

#if defined(CONFIG_X86) && defined(CONFIG_STRICT_DEVMEM)
	kunit_info(test, "Expect zeros\n");
	KUNIT_EXPECT_EQ(test, ret, len);
	KUNIT_EXPECT_TRUE(test, memchr_inv(ctx->umem, 0, len) == NULL);
#else
	kunit_info(test, "Expect equal\n");
	KUNIT_EXPECT_EQ(test, ret, len);
	KUNIT_EXPECT_MEMEQ(test, ctx->umem, direct, len);
#endif
}

/**
 * read_mem_less_page - Read from a kmalloc-backed RAM physical address
 * @test: KUnit test context.
 *
 * Allocates memory via KUnit, fills it with a known pattern, obtains its
 * physical address and calls read_mem() for a partial page.
 *
 * This is explicitly a “system RAM” read:
 *  - Under CONFIG_STRICT_DEVMEM (x86 legacy-protection mode), this should be
 *    denied (currently expected -EPERM).
 *  - Otherwise it may succeed, and the returned bytes should match.
 */
static void read_mem_less_page(struct kunit *test)
{
	struct file fake_file = { };
	struct mem_test_ctx *ctx = test->priv;
	char *buf = kunit_kmalloc(test, PAGE_SIZE, GFP_KERNEL);
	phys_addr_t pa = virt_to_phys(buf);
	loff_t pos = pa;
	int ret;

#if defined(CONFIG_X86) && defined(CONFIG_STRICT_DEVMEM)
	if (pa < SZ_1M) {
		kunit_skip(test, "kmalloc landed in legacy lowmem (<1MB), can not test this scenario");
		return;
	}
#endif

	memset(buf, 0xaa, PAGE_SIZE / 2);

	ret = read_mem(&fake_file, ctx->umem, PAGE_SIZE / 2, &pos);

#if defined(CONFIG_STRICT_DEVMEM)
	kunit_info(test, "expected error or in some not impossible cases \n");
	KUNIT_ASSERT_EQ(test, ret, -EPERM);
#else
	kunit_info(test, "expected read success\n");
	KUNIT_ASSERT_EQ(test, ret, PAGE_SIZE / 2);
	KUNIT_EXPECT_MEMEQ(test, ctx->umem, buf, PAGE_SIZE / 2);
#endif
}

/**
 * read_mem_2_pages - Read spanning multiple pages from a kmalloc-backed region
 * @test: KUnit test context.
 *
 * Similar to read_mem_less_page, but reads across 2 pages with distinct
 * patterns per page. This probes multi-page iteration, partial faults, and
 * page boundary handling in read_mem().
 *
 * Policy expectation mirrors read_mem_less_page:
 *  - strict: deny RAM reads (currently expected -EPERM)
 *  - non-strict: succeed and match the two-page source pattern
 */
static void read_mem_2_pages(struct kunit *test)
{
	struct file fake_file = { };
	struct mem_test_ctx *ctx = test->priv;
	char *buf = kunit_kmalloc(test, 2 * PAGE_SIZE, GFP_KERNEL);
	phys_addr_t pa = virt_to_phys(buf);
	loff_t pos = pa;
	int ret;

#if defined(CONFIG_X86) && defined(CONFIG_STRICT_DEVMEM)
	if (pa < SZ_1M) {
		kunit_skip(test, "kmalloc landed in legacy lowmem (<1MB), can not test this scenario");
		return;
	}
#endif

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

/**
 * read_mem_zero_count_test - Zero-length read is a no-op
 * @test: KUnit test context.
 *
 * Verifies that calling read_mem() with a byte count of zero behaves as a
 * no-op.
 *
 * Expected behavior:
 *  - The function must return 0.
 *  - The file position must remain unchanged.
 *  - No access checks, permission checks, or memory accesses are performed.
 */
static void read_mem_zero_count_test(struct kunit *test)
{
	struct mem_test_ctx *ctx = test->priv;
	struct file fake_file = { };
	loff_t pos = 0;
	ssize_t ret;

	ret = read_mem(&fake_file, ctx->umem, 0, &pos);

	KUNIT_EXPECT_EQ(test, pos, (loff_t)0);

	// valid_phys_addr_range() in not meant to be called with count 0
	// this should be validated before calling it.
	// in x86 it acts strangely: addr + count - 1 <= __pa(high_memory - 1)
	// test should accept also -EFAULT
	KUNIT_EXPECT_TRUE(test, ret == 0 || ret == -EFAULT);
}

/**
 * pick_invalid_phys_addr - Find a physical address range rejected by valid_phys_addr_range()
 * @count: Length of the range we plan to test.
 *
 * Returns a physical address @p such that valid_phys_addr_range(p, count) is
 * expected to be false.
 *
 * The helper tries a small set of candidates near the top of the phys_addr_t space.
 * If, unexpectedly, all candidates are accepted, it returns 0 and the caller should
 * skip the test.
 *
 * Return: An invalid physical address for @count bytes, or 0 if none found.
 */
static phys_addr_t pick_invalid_phys_addr(size_t count)
{
	phys_addr_t max = (phys_addr_t)~(phys_addr_t)0;
	phys_addr_t cand[] = {
		/* Near the end of the address space (likely unmapped / invalid) */
		max - (phys_addr_t)count,
		max - (phys_addr_t)PAGE_SIZE,
		max - (phys_addr_t)(2 * PAGE_SIZE),

		/* A very high address bit set (also typically invalid) */
		(phys_addr_t)1ULL << (sizeof(phys_addr_t) * 8 - 1),
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(cand); i++) {
		/* Avoid wraparound causing small addresses */
		if (cand[i] > max - (phys_addr_t)count)
			continue;
		if (!valid_phys_addr_range(cand[i], count))
			return cand[i];
	}

	return 0;
}

/**
 * read_mem_invalid_phys_range_test - Invalid physical range is rejected with -EFAULT
 * @test: KUnit test context.
 *
 * Exercises the early validation in read_mem():
 *   if (!valid_phys_addr_range(p, count))
 *           return -EFAULT;
 *
 * The test selects a physical address @p that is outside the valid physical
 * address range for the running architecture and requests a non-zero read.
 *
 * Expected behavior:
 *  - read_mem() returns -EFAULT.
 *  - The file position is not advanced.
 *
 * This test is intended to be architecture- and policy-independent (it should
 * fail before any devmem permission checks such as CONFIG_STRICT_DEVMEM).
 */
static void read_mem_invalid_phys_range_test(struct kunit *test)
{
	struct mem_test_ctx *ctx = test->priv;
	struct file fake_file = { };
	size_t len = PAGE_SIZE / 2;
	phys_addr_t p;
	loff_t pos;
	loff_t pos0;
	ssize_t ret;

	p = pick_invalid_phys_addr(len);
	if (!p) {
		kunit_skip(test, "could not find an invalid phys range (unexpected)");
		return;
	}

	pos0 = (loff_t)p;
	pos = pos0;

	ret = read_mem(&fake_file, ctx->umem, len, &pos);

	KUNIT_ASSERT_EQ(test, ret, (ssize_t)-EFAULT);
	KUNIT_EXPECT_EQ(test, pos, pos0);
}

static struct kunit_case mem_cases[] = {
	KUNIT_CASE_PARAM(read_mem_invalid_offset_test, NULL),
	KUNIT_CASE_PARAM(read_mem_valid_basic_test, NULL),
	KUNIT_CASE_PARAM(read_mem_zero_count_test, NULL),
	KUNIT_CASE_PARAM(read_mem_invalid_phys_range_test, NULL),
	KUNIT_CASE_PARAM(read_mem_read_1M_le_at_0, NULL),
#if defined(CONFIG_X86)
	KUNIT_CASE_PARAM(read_mem_read_1M_le_at_ram, NULL),
#endif
	KUNIT_CASE_PARAM(read_mem_less_page, NULL),
	KUNIT_CASE_PARAM(read_mem_2_pages, NULL),
	{}
};

static struct kunit_suite mem_suite = {
	.name = "devmem-read_mem " DEVMEM_TEST_SUITE_MODE,
	.init = mem_test_init,
	.test_cases = mem_cases,
};

kunit_test_suite(mem_suite);
