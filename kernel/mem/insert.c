#include <types.h>
#include <paging.h>

#include <kernel/mem.h>

struct insert_info {
	struct page_table *pml4;
	struct page_info *page;
	uint64_t flags;
};

/* If the PTE already points to a present page, the reference count of the page
 * gets decremented and the TLB gets invalidated. Then this function increments
 * the reference count of the new page and sets the PTE to the new page with
 * the user-provided permissions.
 */
static int insert_pte(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct insert_info *info = walker->udata;
	struct page_info *page;

	/* LAB 2: your code here. */
	if(*entry & PAGE_PRESENT){
		page = pa2page(PAGE_ADDR(*entry));
		page_decref(page);
		tlb_invalidate(info->pml4,page2kva(page));
	}

	++info->page->pp_ref;
	*entry = page2pa(info->page) | info->flags | PAGE_PRESENT;

	return 0;
}

/* If the PDE already points to a present huge page, the reference count of the
 * huge page gets decremented and the TLB gets invalidated. Then if the new
 * page is a 4K page, this function calls ptbl_alloc() to allocate a new page
 * table. If the new page is a 2M page, this function increments the reference
 * count of the new page and sets the PDE to the new huge page with the
 * user-provided permissions.
 */
static int insert_pde(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct insert_info *info = walker->udata;
	struct page_info *page;

	/* LAB 2: your code here. */
	if(*entry & PAGE_PRESENT){
		page = pa2page(PAGE_ADDR(*entry));
		page_decref(page);
		tlb_invalidate(info->pml4,page2kva(page));
	}

	ptbl_alloc(entry,base,end,walker);
	//huge page bonus?

	return 0;
}


/* Map the physical page page at virtual address va. The flags argument
 * contains the permission to set for the PTE. The PAGE_PRESENT flag should
 * always be set.
 *
 * Requirements:
 *  - If there is already a page mapped at va, it should be removed using
 *    page_decref().
 *  - If necessary, a page should be allocated and inserted into the page table
 *    on demand. This can be done by providing ptbl_alloc() to the page walker.
 *  - The reference count of the page should be incremented upon a successful
 *    insertion of the page.
 *  - The TLB must be invalidated if a page was previously present at va.
 *
 * Corner-case hint: make sure to consider what happens when the same page is
 * re-inserted at the same virtual address in the same page table. However, do
 * not try to distinguish this case in your code, as this frequently leads to
 * subtle bugs. There is another elegant way to handle everything in the same
 * code path.
 *
 * Hint: what should happen when the user inserts a 2M huge page at a
 * misaligned address?
 *
 * Hint: this function calls walk_page_range(), hpage_aligned()and page2pa().
 */
int page_insert(struct page_table *pml4, struct page_info *page, void *va,
    uint64_t flags)
{
	/* LAB 2: your code here. */
	struct insert_info info = {
		.pml4 = pml4,
		.flags = flags | PAGE_PRESENT,
		.page = page
	};

	struct page_walker walker = {
		.get_pte = insert_pte,
		.get_pde = ptbl_alloc,
		.get_pdpte = ptbl_alloc,
		.get_pml4e = ptbl_alloc,
		.udata = &info,
	};

	return walk_page_range(pml4, va, (void *)((uintptr_t)va + PAGE_SIZE),
		&walker);
}

