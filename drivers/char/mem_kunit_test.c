/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TODO: comment
 */

#include <kunit/test.h>

#include <linux/io.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/ioport.h>
#include <asm-generic/io.h>

#include "mem.h"

#define MAX_READ 8

/**
 * enum phys_addr_type - Categories of physical address ranges for /dev/mem policy tests
 * @PHYS_INVALID:     A range guaranteed to fail valid_phys_addr_range().
 * @PHYS_SYSTEM_RAM:  A physical address backed by System RAM (kmalloc-backed page).
 * @PHYS_IO_FREE:     A non-System-RAM IORESOURCE_MEM range which is not busy/claimed.
 * @PHYS_IO_CLAIMED:  A non-System-RAM IORESOURCE_MEM range which is busy/claimed.
 * @PHYS_RESTRICTED:  System RAM marked as reserved for DEVMEM.
 *
 * These categories map to the two policy gates relevant to /dev/mem:
 *  - CONFIG_STRICT_DEVMEM (Gate 1): blocks System RAM.
 *  - CONFIG_IO_STRICT_DEVMEM (Gate 2): blocks claimed/busy MMIO regions.
 */
enum phys_addr_type {
	PHYS_INVALID = 0,
	PHYS_SYSTEM_RAM,
	PHYS_IO_FREE,
	PHYS_IO_CLAIMED,
	PHYS_RESTRICTED,
	PHYS_EDGE_MEM,
};

/**
 * struct read_request - Description of a read_mem() test operation
 * @phys_addr_type: Physical address category to test (RAM, IO, invalid, etc.).
 * @count: Total number of bytes to read.
 * @invalid_user: Creates an invalid userspace address as destination.
 * @read_operations_cnt: Number of read_mem() calls to perform.
 * @split_evenly: If true, @count is split across multiple reads.
 * @start_offset: Offset added to the base physical address before reading.
 * @seed_ram: If true, seed backing RAM before performing the read.
 * @seed_pattern: Byte pattern used when seeding RAM.
 *
 * The structure contains *no policy*, it only describes what to execute.
 * Policy checks and assertions are performed using the resulting
 * read_results structure.
 */
struct read_request {
	enum phys_addr_type phys_addr_type;
	size_t count;
	bool invalid_user;
	int read_operations_cnt;
	bool split_evenly;
	size_t start_offset;
	bool seed_ram;
	u8 seed_pattern;
};

/**
 * struct read_results - Collected results of a read_mem() test
 * @check_ppos: Whether the caller expects file position checks.
 * @check_content: Whether the caller expects content verification.
 * @skipped: Set if the test could not be executed on this platform.
 * @base_phys: Base physical address used for the test.
 * @start_pos: Initial file position before the first read.
 * @end_pos: File position after the final read.
 * @ret_value: Return value of each read_mem() call.
 * @pos_before: File position before each read.
 * @pos_after: File position after each read.
 * @backing_kbuf: Pointer to backing RAM (if applicable).
 * @backing_kbuf_sz: Size of the backing RAM buffer.
 *
 * Holds all observable outcomes of a read_mem() test execution.
 * This structure is populated by read_mem_action() and then
 * examined by test-specific assertion helpers.
 */
struct read_results {
	bool check_ppos;
	bool check_content;
	bool skipped;
	char *skipped_reason;

	phys_addr_t base_phys;
	loff_t start_pos;
	loff_t end_pos;
	unsigned long flags;

	ssize_t ret_value[MAX_READ];
	loff_t pos_before[MAX_READ];
	loff_t pos_after[MAX_READ];

	 /* only set for PHYS_SYSTEM_RAM */
	void *backing_kbuf;
	size_t backing_kbuf_sz;
};

/**
 * struct pick_ctx - Context for physical address selection
 * @count: Number of bytes required at the selected address.
 * @found: Selected physical address (0 if none found).
 * @want_busy: If true, select a resource marked IORESOURCE_BUSY.
 * @want_free: If true, select a resource not marked IORESOURCE_BUSY.
 * @found_flags: Resource flags of the selected address.
 *
 * This structure is populated by pick_iomem_cb() during
 * walk_iomem_res_desc() traversal.
 */
struct pick_ctx {
	struct kunit *test; // debug
	size_t count;
	phys_addr_t found;
	unsigned long found_flags;
	bool want_busy;
	bool want_free;
};

/**
 * struct mem_test_ctx - Per-test memory context
 * @umem: Userspace-mapped buffer used as the read_mem() destination.
 * @size: Size of the allocated buffers.
 *
 * This structure holds all per-test state shared across test cases.
 * It is initialized in mem_test_init() and stored in test->priv.
 *
 * The @umem buffer is used as the destination for read_mem().
 */
struct mem_test_ctx {
	char __user *umem;
	size_t size;
};

/**
 * phys_addr_type_str - Convert a phys_addr_type enum to a printable string
 * @t: Physical address type.
 *
 * Returns a constant string describing the given physical address category.
 */
static char *phys_addr_type_str(enum phys_addr_type t) {
	switch (t) {
		case PHYS_INVALID:
			return "PHYS_INVALID";
	        case PHYS_SYSTEM_RAM:
			return "PHYS_SYSTEM_RAM";
		case PHYS_IO_FREE:
			return "PHYS_IO_FREE";
		case PHYS_IO_CLAIMED:
			return "PHYS_IO_CLAIMED";
		case PHYS_RESTRICTED:
			return "PHYS_RESTRICTED";
		case PHYS_EDGE_MEM:
			return "PHYS_EDGE_MEM";
		default:
			return "UNKNOWN";
	}
}

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
 * pick_restricted_phys_addr - Find a "restricted" physical address
 * @test: KUnit test context.
 * @count: Number of bytes that must be readable from the address.
 *
 * This corresponds to legacy x86 behavior where reads are permitted
 * but sanitized (zero-filled) under CONFIG_STRICT_DEVMEM.
 *
 * The function performs a bounded scan of low physical memory and
 * returns the first suitable address found. If no such address exists
 * on the running platform, returns 0 and the caller should skip the test.
 */
static phys_addr_t pick_restricted_phys_addr(struct kunit *test, size_t count)
{
#if !defined(CONFIG_STRICT_DEVMEM)
	kunit_info(test, "# CONFIG_STRICT_DEVMEM is not set, no restricted memory\n");
	return 0;
#else
	phys_addr_t p;
	const phys_addr_t start = 0;
	const phys_addr_t end = SZ_1M;
	const phys_addr_t step = PAGE_SIZE;

	if (count == 0)
		return 0;

	for (p = start; p + count <= end; p += step) {
		unsigned long pfn;

		if (!valid_phys_addr_range(p, count))
			continue;

		pfn = PHYS_PFN(p);

		if (page_is_allowed(pfn) == 2)
			return p;
	}

	return 0;
#endif
}

/**
 * pick_mixed_policy_phys_addr - Find a range spanning restricted -> denied pages
 * @test: KUnit test context.
 * @count: Number of bytes to read.
 *
 * Finds a physical address such that:
 *   - the first page is "restricted" (page_is_allowed() == 2)
 *   - the next page is "denied"     (page_is_allowed() == 0)
 *
 * Returns:
 *   Physical address suitable for a mixed-policy read, or 0 if none found.
 */
static phys_addr_t pick_mixed_policy_phys_addr(struct kunit *test, size_t count)
{
#if !defined(CONFIG_STRICT_DEVMEM)
	return 0;
#else
	phys_addr_t base;
	unsigned long pfn;
	phys_addr_t start;

	if (count < 2)
		return 0;

	base = pick_restricted_phys_addr(test, PAGE_SIZE);
	if (!base)
		return 0;

	pfn = PHYS_PFN(base);

	if (page_is_allowed(pfn + 1) == 0) {
		start = PFN_PHYS(pfn) + PAGE_SIZE - 1;

		if (valid_phys_addr_range(start, count))
			return start;
	}

	if (pfn > 0 && page_is_allowed(pfn - 1) == 0) {
		start = PFN_PHYS(pfn) - 1;

		if (valid_phys_addr_range(start, count))
			return start;
	}

	kunit_info(test,
		   "pick_mixed_policy_phys_addr: no adjacent denied page found\n");
	return 0;
#endif
}

/**
 * pick_iomem_cb - Resource tree callback for selecting MMIO regions
 * @res: Current resource node.
 * @arg: Pointer to struct pick_ctx.
 *
 * Used by walk_iomem_res_desc() to locate a candidate MMIO region
 * matching the requested criteria (free or claimed).
 *
 * The callback:
 *  - filters for IORESOURCE_MEM regions
 *  - excludes System RAM
 *  - checks busy/free status depending on request
 *  - ensures the region is large enough
 *
 * On success, stores the base physical address in ctx->found and
 * returns 1 to stop the walk.
 *
 * Returns 0 to continue scanning.
 */
static int pick_iomem_cb(struct resource *res, void *arg)
{
	struct pick_ctx *ctx = arg;
	u64 len;

	if (!res)
		return 0;

	if (!(res->flags & IORESOURCE_MEM))
		return 0;
	if (res->flags & IORESOURCE_SYSTEM_RAM)
		return 0;

	if (ctx->want_busy && !(res->flags & IORESOURCE_BUSY))
		return 0;
	if (ctx->want_free && (res->flags & IORESOURCE_BUSY))
		return 0;

	if (res->end < res->start)
		return 0;
	len = (u64)res->end - (u64)res->start + 1;
	if (len < ctx->count)
		return 0;

	if (!valid_phys_addr_range(res->start, ctx->count))
		return 0;

	ctx->found = res->start;
	return 1;
}

/**
 * pick_invalid_phys_addr - Select a physical address rejected by read_mem()
 * @test: KUnit test context.
 * @count: Size of the access that will be attempted.
 *
 * Returns a physical address that is guaranteed to fail
 * valid_phys_addr_range(), typically just beyond the end of RAM.
 *
 * This is used to verify that read_mem() correctly rejects
 * invalid physical address ranges with -EFAULT.
 *
 * Returns 0 if no such address can be constructed.
 */
static phys_addr_t pick_invalid_phys_addr(struct kunit *test, size_t count)
{
	phys_addr_t max = (phys_addr_t)~(phys_addr_t)0;
	phys_addr_t cand[] = {
		max - (phys_addr_t)count,
		max - (phys_addr_t)PAGE_SIZE,
		max - (phys_addr_t)(2 * PAGE_SIZE),

		(phys_addr_t)1ULL << (sizeof(phys_addr_t) * 8 - 1),
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(cand); i++) {
		if (cand[i] > max - (phys_addr_t)count)
			continue;
		if (!valid_phys_addr_range(cand[i], count))
			return cand[i];
	}

	return 0;
}

/**
 * pick_phys_addr_type - Select a physical address of a given category
 * @test: KUnit test context.
 * @count: Size of the read to be performed.
 * @t: Requested physical address type.
 * @ram_buf: Optional output pointer to backing RAM buffer.
 *
 * Selects a physical address suitable for testing read_mem() based on
 * the requested address category:
 *
 *   PHYS_INVALID      - address rejected by valid_phys_addr_range()
 *   PHYS_SYSTEM_RAM   - kmalloc-backed RAM
 *   PHYS_IO_FREE      - unclaimed MMIO region
 *   PHYS_IO_CLAIMED   - claimed MMIO region
 *   PHYS_RESTRICTED   - address returning sanitized reads
 *
 * Returns the selected physical address, or 0 if no suitable address
 * exists on the current platform.
 */
static phys_addr_t pick_phys_addr_type(struct kunit *test, size_t count,
				       enum phys_addr_type t, void **ram_buf)
{
	void *buf;
	struct pick_ctx ctx = {
		.count = count,
		.found = 0,
	};

	kunit_info(test, "%s: count=%zu, type=%s\n", __func__, count, phys_addr_type_str(t));

	if (ram_buf)
		*ram_buf = NULL;

	switch (t) {
	case PHYS_INVALID:
		return pick_invalid_phys_addr(test, count);

	case PHYS_SYSTEM_RAM:
		buf = kunit_kmalloc(test, PAGE_SIZE, GFP_KERNEL);
		if (!buf)
			return 0;

		if (ram_buf)
			*ram_buf = buf;

		if (count > PAGE_SIZE) {
			kunit_info(test,
				   "pick_phys_addr_type: requested %zu > PAGE_SIZE for RAM\n",
				   count);
			return 0;
		}

		memset(buf, 0xA5, PAGE_SIZE);
		return virt_to_phys(buf);

	case PHYS_IO_FREE:
		ctx.want_free = true;
		walk_iomem_res_desc(IORES_DESC_NONE, (u64)~0ULL, IORESOURCE_MEM, IORES_DESC_NONE,
				    &ctx, pick_iomem_cb);
		return ctx.found;

	case PHYS_IO_CLAIMED:
		ctx.want_busy = true;
		ctx.test = test;
		walk_iomem_res_desc(IORES_DESC_NONE, (u64)~0ULL, IORESOURCE_MEM, IORES_DESC_NONE,
				    &ctx, pick_iomem_cb);
		return ctx.found;

	case PHYS_RESTRICTED:
		return pick_restricted_phys_addr(test, count);

	case PHYS_EDGE_MEM:
		return pick_mixed_policy_phys_addr(test, count);

	default:
		return 0;
	}
}

/**
 * mem_test_init - Initialize per-test memory context
 * @test: KUnit test context.
 *
 * Allocates and initializes the per-test mem_test_ctx structure.
 * This includes:
 *  - allocating a kernel buffer for RAM-backed tests
 *  - creating a user-mapped buffer used as the read_mem() destination
 *
 * The initialized context is stored in test->priv.
 *
 * Returns 0 on success or a negative errno on failure.
 */
static int mem_test_init(struct kunit *test)
{
	unsigned long user_addr;
	struct mem_test_ctx *ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, ctx);
	test->priv = ctx;
	ctx->size = PAGE_SIZE * 4;

	user_addr = kunit_vm_mmap(test, NULL, 0, ctx->size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0);
	KUNIT_ASSERT_NE_MSG(test, user_addr, 0, "Could not create userspace mm");
	KUNIT_ASSERT_LT_MSG(test, user_addr, (unsigned long)TASK_SIZE, "Failed to allocate user memory");
	ctx->umem = (char __user *)user_addr;
	return 0;
}

/**
 * read_mem_action - Execute one or more read_mem() operations
 * @test: KUnit test context.
 * @ctx: Test memory context.
 * @r: Description of the read request.
 * @res: Structure populated with observed results.
 *
 * This helper performs the actual read_mem() calls for most tests.
 * It:
 *  - selects a physical address based on request type
 *  - optionally seeds backing memory
 *  - performs one or more reads
 *  - records return values and ppos movement
 *
 * No assertions are performed here; validation is done by the caller.
 */
static void read_mem_action(struct kunit *test, struct mem_test_ctx *ctx,
			    const struct read_request *r,
			    struct read_results *res)
{
	struct file fake_file = { };
	void *ram_buf = NULL;
	size_t total = r->count;
	size_t per = 0, rem = 0;
	int i, n;
	loff_t pos;
	ssize_t ret;
	char __user *user_buffer = ctx->umem;

	if (r->invalid_user) user_buffer = (char __user *) 1;
	memset(res, 0, sizeof(*res));
	res->skipped = false;

	n = r->read_operations_cnt;
	if ((n > MAX_READ) || (n <= 0)) {
		kunit_info(test, "read_mem_action: ops=%d > MAX_READ=%d, skipping\n",
			   n, MAX_READ);
		res->skipped = true;
		res->skipped_reason = "Required operation cnt invalid";
		return;
	}

	res->base_phys = pick_phys_addr_type(test, max_t(size_t, total, 1),
					     r->phys_addr_type, &ram_buf);
	if (!res->base_phys) {
		kunit_info(test, "read_mem_action: could not pick phys type %s, skipping\n",
			   phys_addr_type_str(r->phys_addr_type));
		res->skipped = true;
		res->skipped_reason = "Can not find any requested address type";
		return;
	}

	res->base_phys += r->start_offset;

	if (r->seed_ram) {
		if (r->phys_addr_type != PHYS_SYSTEM_RAM || !ram_buf) {
			kunit_info(test, "read_mem_action: seed requested but no RAM backing, skipping seed\n");
		} else {
			memset(ram_buf, r->seed_pattern, PAGE_SIZE);
		}
	}

	if (r->split_evenly && n > 1) {
		per = total / n;
		rem = total % n;
		if (per == 0) {
			kunit_info(test, "read_mem_action: count=%zu too small for ops=%d, forcing single op\n",
				   total, n);
			n = 1;
			per = 0;
			rem = 0;
		}
	}

	pos = (loff_t)res->base_phys;
	res->start_pos = pos;

	kunit_info(test,
		   "read_mem_action: type=%d base_phys=0x%llx start_offset=%zu count=%zu ops=%d\n",
		   r->phys_addr_type,
		   (unsigned long long)res->base_phys,
		   r->start_offset, total, n);

	for (i = 0; i < n; i++) {
		size_t this_cnt;

		if (n == 1) {
			this_cnt = total;
		} else if (r->split_evenly) {
			this_cnt = per + (i < rem ? 1 : 0);
		} else {
			this_cnt = (i == 0) ? total : 0;
		}

		res->pos_before[i] = pos;

		if (this_cnt == 0) {
			res->ret_value[i] = 0;
			res->pos_after[i] = pos;
			continue;
		}

		ret = read_mem(&fake_file,
			       (char __user *)(user_buffer + (size_t)(res->pos_before[i] - res->start_pos)),
			       this_cnt,
			       &pos);

		res->ret_value[i] = ret;
		res->pos_after[i] = pos;

		kunit_info(test,
			   "  op[%d]: req=%zu pos_before=0x%llx ret=%zd pos_after=0x%llx\n",
			   i, this_cnt,
			   (unsigned long long)res->pos_before[i],
			   ret,
			   (unsigned long long)res->pos_after[i]);
	}

	res->end_pos = pos;

	if (r->phys_addr_type == PHYS_SYSTEM_RAM && ram_buf) {
		res->backing_kbuf = ram_buf;
		res->backing_kbuf_sz = PAGE_SIZE;
	}
}

/**
 * read_mem_invalid_addr_test - Verify invalid physical address handling
 * @test: KUnit test context.
 *
 * Ensures that read_mem() correctly rejects physical addresses that
 * fall outside valid_phys_addr_range(), returning -EFAULT and leaving
 * the file position unchanged.
 */
static void read_mem_invalid_addr_test(struct kunit *test)
{
	struct mem_test_ctx *ctx = test->priv;
	struct read_request req = {
		.phys_addr_type = PHYS_INVALID,
		.count = 64,
		.invalid_user = false,
		.read_operations_cnt = 1,
		.start_offset = 0,
		.seed_ram = false,
	};
	struct read_results res;

	read_mem_action(test, ctx, &req, &res);

	if (res.skipped) {
		kunit_skip(test, "Skip reason:%s\n", res.skipped_reason);
		return;
	}
	KUNIT_EXPECT_EQ(test, res.ret_value[0], -EFAULT);
	KUNIT_EXPECT_EQ(test, res.pos_after[0], res.pos_before[0]);
}

/**
 * read_mem_restricted_addr_single_test - Test restricted read behavior
 * @test: KUnit test context.
 *
 * Exercises the case where page_is_allowed() returns the "restricted"
 * result (typically x86 + CONFIG_STRICT_DEVMEM).
 *
 * Expected behavior:
 *  - read succeeds
 *  - data is sanitized (zero-filled)
 *  - ppos is advanced
 */
static void read_mem_restricted_addr_single_test(struct kunit *test)
{
	struct mem_test_ctx *ctx = test->priv;
	struct read_request req = {
		.phys_addr_type = PHYS_RESTRICTED,
		.count = 64,
		.invalid_user = false,
		.read_operations_cnt = 1,
		.start_offset = 0,
		.seed_ram = true,
		.seed_pattern = 0xaa,
	};
	struct read_results res;

	read_mem_action(test, ctx, &req, &res);

	if (res.skipped) {
		kunit_skip(test, "Skip reason:%s\n", res.skipped_reason);
		return;
	}

	KUNIT_EXPECT_EQ(test, res.ret_value[0], req.count);
	KUNIT_EXPECT_EQ(test, res.pos_after[0], res.pos_before[0] + req.count);
#if defined(CONFIG_STRICT_DEVMEM)
	kunit_info(test, "\"CONFIG_STRICT_DEVMEM=y\" case, expected to be 0\n");
	KUNIT_EXPECT_TRUE(test, memchr_inv(ctx->umem, 0, req.count) == NULL);
#else
	kunit_info(test, "\"# CONFIG_STRICT_DEVMEM is not set\" case, expected to be 0\n");
	KUNIT_EXPECT_MEMEQ(test, ctx->umem, (u8 *)res.backing_kbuf, req.count);
#endif
}

/**
 * read_mem_ram_addr_single_test - Read from System RAM
 * @test: KUnit test context.
 *
 * Verifies read_mem() behavior when accessing normal System RAM.
 *
 * Expected behavior:
 *  - CONFIG_STRICT_DEVMEM: access denied (-EPERM)
 *  - otherwise: read succeeds and data matches backing memory
 */
static void read_mem_ram_addr_single_test(struct kunit *test)
{
	struct mem_test_ctx *ctx = test->priv;
	struct read_request req = {
		.phys_addr_type = PHYS_SYSTEM_RAM,
		.count = 64,
		.invalid_user = false,
		.read_operations_cnt = 1,
		.start_offset = 0,
		.seed_ram = true,
		.seed_pattern = 0xaa,
	};
	struct read_results res;

	read_mem_action(test, ctx, &req, &res);

	if (res.skipped) {
		kunit_skip(test, "Skip reason:%s\n", res.skipped_reason);
		return;
	}

#if defined(CONFIG_STRICT_DEVMEM)
	kunit_info(test, "\"CONFIG_STRICT_DEVMEM=y\" case, expected to fail\n");
	KUNIT_EXPECT_EQ(test, res.ret_value[0], -EPERM);
	KUNIT_EXPECT_EQ(test, res.pos_after[0], res.pos_before[0]);
#else
	kunit_info(test, "\"# CONFIG_STRICT_DEVMEM is not set\" case, expected to match the memory contents\n");
	KUNIT_EXPECT_EQ(test, res.ret_value[0], req.count);
	KUNIT_EXPECT_EQ(test, res.pos_after[0], res.pos_before[0] + req.count);
	KUNIT_EXPECT_MEMEQ(test, ctx->umem, (u8 *)res.backing_kbuf, req.count);
#endif
}

/**
 * read_mem_ram_addr_single_edge_test - Read across a RAM edge with policy enforcement
 * @test: KUnit test context.
 *
 * This test verifies read_mem() behavior when accessing a System RAM address
 * that lies at a policy boundary (“edge case”), where access permissions may
 * change across pages.
 *
 * The test uses a RAM-backed physical address and performs a single read
 * operation. The backing memory is seeded so that content verification is
 * possible when access is allowed.
 */
static void read_mem_ram_addr_single_edge_test(struct kunit *test)
{
	struct mem_test_ctx *ctx = test->priv;
	struct read_request req = {
		.phys_addr_type = PHYS_SYSTEM_RAM,
		.count = 64,
		.invalid_user = false,
		.read_operations_cnt = 1,
		.start_offset = 0,
		.seed_ram = true,
		.seed_pattern = 0xaa,
	};
	struct read_results res;

	read_mem_action(test, ctx, &req, &res);

	if (res.skipped) {
		kunit_skip(test, "Skip reason:%s\n", res.skipped_reason);
		return;
	}

#if defined(CONFIG_STRICT_DEVMEM)
	kunit_info(test, "\"CONFIG_STRICT_DEVMEM=y\" case, expected to fail\n");
	KUNIT_EXPECT_EQ(test, res.ret_value[0], -EPERM);
	KUNIT_EXPECT_EQ(test, res.pos_after[0], res.pos_before[0]);
#else
	kunit_info(test, "\"# CONFIG_STRICT_DEVMEM is not set\" case, expected to match the memory contents\n");
	KUNIT_EXPECT_EQ(test, res.ret_value[0], -EPERM);
	KUNIT_EXPECT_EQ(test, res.pos_after[0], res.pos_before[0] + req.count);
	KUNIT_EXPECT_MEMEQ(test, ctx->umem, (u8 *)res.backing_kbuf, req.count);
#endif
}

/**
 * read_mem_ram_addr_single_invalid_user_test - Reject read when user buffer is invalid
 * @test: KUnit test context.
 *
 * Verifies that read_mem() correctly returns -EFAULT when the destination
 * user-space buffer is invalid, even if the physical address itself is valid.
 *
 * The test uses a valid System RAM physical address, but forces an invalid
 * user-space destination pointer. The expected behavior is:
 *
 *   - read_mem() returns -EFAULT
 *   - the file position (*ppos) is not advanced
 */
static void read_mem_ram_addr_single_invalid_user_test(struct kunit *test)
{
	struct mem_test_ctx *ctx = test->priv;
	struct read_request req = {
		.phys_addr_type = PHYS_SYSTEM_RAM,
		.count = 64,
		.invalid_user = true,
		.read_operations_cnt = 1,
		.start_offset = 0,
		.seed_ram = true,
		.seed_pattern = 0xaa,
	};
	struct read_results res;

	read_mem_action(test, ctx, &req, &res);

	if (res.skipped) {
		kunit_skip(test, "Skip reason:%s\n", res.skipped_reason);
		return;
	}
#if defined(CONFIG_STRICT_DEVMEM)
	KUNIT_EXPECT_EQ(test, res.ret_value[0], -EPERM);
#else
	KUNIT_EXPECT_EQ(test, res.ret_value[0], -EFAULT);
#endif
	KUNIT_EXPECT_EQ(test, res.pos_after[0], res.pos_before[0]);
}

/**
 * read_mem_cross_page_multi_test - Read across page boundary
 * @test: KUnit test context.
 *
 * Performs multiple read_mem() calls starting from an unaligned
 * physical address such that the read crosses a page boundary.
 *
 * Validates:
 *  - correct ppos advancement
 *  - correct multi-read sequencing
 *  - correct data returned for non-strict configurations
 */
static void read_mem_cross_page_multi_test(struct kunit *test)
{
	struct mem_test_ctx *ctx = test->priv;
	struct read_request req = {
		.phys_addr_type = PHYS_SYSTEM_RAM,
		.count = PAGE_SIZE,
		.invalid_user = false,
		.read_operations_cnt = 4,
		.split_evenly = true,
		.start_offset = 16,
		.seed_ram = true,
		.seed_pattern = 0xaa,
	};
	struct read_results res;

	read_mem_action(test, ctx, &req, &res);

	if (res.skipped) {
		kunit_skip(test, "Skip reason:%s\n", res.skipped_reason);
		return;
	}

#if defined(CONFIG_STRICT_DEVMEM)
	kunit_info(test, "\"CONFIG_STRICT_DEVMEM=y\" case, expected to fail\n");
	KUNIT_EXPECT_EQ(test, res.ret_value[0], -EPERM);
	KUNIT_EXPECT_EQ(test, res.pos_after[0], res.pos_before[0]);
#else
	ssize_t ret = 0;
	loff_t expected_pos;
	int i;

	expected_pos = res.start_pos;
	kunit_info(test, "\"# CONFIG_STRICT_DEVMEM is not set\" case, expected to match the memory contents\n");
	for (i = 0; i < req.read_operations_cnt && i < MAX_READ; i++) {
		ret = res.ret_value[i];
		if (ret < 0)
			KUNIT_FAIL(test, "op[%d] failed ret=%zd", i, ret);

		KUNIT_EXPECT_EQ(test, res.pos_before[i], expected_pos);
		expected_pos += ret;
		KUNIT_EXPECT_EQ(test, res.pos_after[i], expected_pos);
	}
	KUNIT_EXPECT_MEMEQ(test, ctx->umem, (u8 *)res.backing_kbuf, req.count);
#endif
}

#ifdef CONFIG_DEVMEM_KUNIT_TEST_IO

/**
 * read_mem_io_free_addr_single_test - Read from unclaimed MMIO
 * @test: KUnit test context.
 *
 * Tests read_mem() behavior when accessing an MMIO region not claimed
 * by a kernel driver.
 *
 * Expected behavior:
 *  - allowed when CONFIG_IO_STRICT_DEVMEM is disabled
 *  - denied when CONFIG_IO_STRICT_DEVMEM is enabled
 */
static void read_mem_io_free_addr_single_test(struct kunit *test)
{
	struct mem_test_ctx *ctx = test->priv;
	struct read_request req = {
		.phys_addr_type = PHYS_IO_FREE,
		.count = 1,
		.invalid_user = false,
		.read_operations_cnt = 1,
		.start_offset = 0,
		.seed_ram = false,
	};
	struct read_results res;

	read_mem_action(test, ctx, &req, &res);

	if (res.skipped) {
		kunit_skip(test, "Skip reason:%s\n", res.skipped_reason);
		return;
	}

	KUNIT_EXPECT_EQ(test, res.ret_value[0], 1);
	KUNIT_EXPECT_EQ(test, res.pos_after[0], res.pos_before[0] + 1);
}

/**
 * read_mem_io_claimed_addr_single_test - Read from claimed MMIO region
 * @test: KUnit test context.
 *
 * Verifies that read_mem() correctly enforces CONFIG_IO_STRICT_DEVMEM
 * by denying access to MMIO regions already claimed by a driver.
 */
static void read_mem_io_claimed_addr_single_test(struct kunit *test)
{
	struct mem_test_ctx *ctx = test->priv;
	struct read_request req = {
		.phys_addr_type = PHYS_IO_CLAIMED,
		.count = 1,
		.invalid_user = false,
		.read_operations_cnt = 1,
		.start_offset = 0,
		.seed_ram = false,
	};
	struct read_results res;

	read_mem_action(test, ctx, &req, &res);

	if (res.skipped) {
		kunit_skip(test, "Skip reason:%s\n", res.skipped_reason);
		return;
	}

#if defined(CONFIG_IO_STRICT_DEVMEM)
	kunit_info(test, "\"CONFIG_IO_STRICT_DEVMEM=y\" case, expected to fail\n");
	KUNIT_EXPECT_EQ(test, res.ret_value[0], -EPERM);
	KUNIT_EXPECT_EQ(test, res.pos_after[0], res.pos_before[0]);
#else
	kunit_info(test, "\"# CONFIG_IO_STRICT_DEVMEM is not set\" case, to success\n");
	KUNIT_EXPECT_EQ(test, res.ret_value[0], 1);
	KUNIT_EXPECT_EQ(test, res.pos_after[0], res.pos_before[0] + 1);
#endif
}
#endif //CONFIG_DEVMEM_KUNIT_TEST_IO

/**
 * read_mem_zero_count_test - Verify behavior for zero-length reads
 * @test: KUnit test context.
 *
 * Confirms that read_mem() correctly handles a zero-length read.
 * Per POSIX semantics, this may either return 0 or return an error
 * if parameter validation is performed.
 *
 * The test verifies that:
 *  - no memory is modified
 *  - file position is not advanced
 */
static void read_mem_zero_count_test(struct kunit *test)
{
	struct mem_test_ctx *ctx = test->priv;
	struct file fake_file = { };
	loff_t ppos = 0;
	loff_t ppos0 = ppos;
	ssize_t ret;

	ret = read_mem(&fake_file, ctx->umem, 0, &ppos);

	KUNIT_EXPECT_EQ(test, ppos, (loff_t)0);

	KUNIT_EXPECT_TRUE(test, ret == 0 || ret == -EFAULT);
	KUNIT_EXPECT_EQ(test, ppos, ppos0);
}

static struct kunit_case mem_cases[] = {
	KUNIT_CASE(read_mem_zero_count_test),
	KUNIT_CASE(read_mem_invalid_addr_test),
	KUNIT_CASE(read_mem_restricted_addr_single_test),
	KUNIT_CASE(read_mem_ram_addr_single_test),
	KUNIT_CASE(read_mem_cross_page_multi_test),
	KUNIT_CASE(read_mem_ram_addr_single_invalid_user_test),
	KUNIT_CASE(read_mem_ram_addr_single_edge_test),
#ifdef CONFIG_DEVMEM_KUNIT_TEST_IO
	KUNIT_CASE(read_mem_io_free_addr_single_test),
	KUNIT_CASE(read_mem_io_claimed_addr_single_test),
#endif
	{}
};

static struct kunit_suite mem_suite = {
	.name = "devmem-read_mem",
	.init = mem_test_init,
	.test_cases = mem_cases,
};

kunit_test_suite(mem_suite);
