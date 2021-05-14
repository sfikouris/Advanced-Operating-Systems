#include <types.h>
#include <list.h>
#include <paging.h>
#include <spinlock.h>
#include <string.h>

#include <kernel/mem.h>

/* Physical page metadata. */
size_t npages;
struct page_info *pages;

/* Lists of physical pages. */
struct list page_free_list[BUDDY_MAX_ORDER];

#ifdef USE_BUDDY_LOCK
/* Lock for the buddy allocator. */
struct spinlock buddy_lock = {
#ifdef DEBUG_SPINLOCK
	.name = "buddy_lock",
#endif
};
#endif

/* Counts the number of free pages for the given order.
 */
size_t count_free_pages(size_t order)
{
	struct list *node;
	size_t nfree_pages = 0;

	if (order >= BUDDY_MAX_ORDER) {
		return 0;
	}

	list_foreach(page_free_list + order, node) {
		++nfree_pages;
	}

	return nfree_pages;
}

/* Shows the number of free pages in the buddy allocator as well as the amount
 * of free memory in kiB.
 *
 * Use this function to diagnose your buddy allocator.
 */
void show_buddy_info(void)
{
	struct page_info *page;
	struct list *node;
	size_t order;
	size_t nfree_pages;
	size_t nfree = 0;

	cprintf("Buddy allocator:\n");

	for (order = 0; order < BUDDY_MAX_ORDER; ++order) {
		nfree_pages = count_free_pages(order);

		cprintf("  order #%u pages=%u\n", order, nfree_pages);

		nfree += nfree_pages * (1 << (order + 12));
	}

	cprintf("  free: %u kiB\n", nfree / 1024);
}

/* Gets the total amount of free pages. */
size_t count_total_free_pages(void)
{
	struct page_info *page;
	struct list *node;
	size_t order;
	size_t nfree_pages;
	size_t nfree = 0;

	for (order = 0; order < BUDDY_MAX_ORDER; ++order) {
		nfree_pages = count_free_pages(order);
		nfree += nfree_pages * (order + 1);
	}

	return nfree;
}

/* Splits lhs into free pages until the order of the page is the requested
 * order req_order.
 *
 * The algorithm to split pages is as follows:
 *  - Given the page of order k, locate the page and its buddy at order k - 1.
 *  - Decrement the order of both the page and its buddy.
 *  - Mark the buddy page as free and add it to the free list.
 *  - Repeat until the page is of the requested order.
 *
 * Returns a page of the requested order.
 */
 struct page_info *buddy_split(struct page_info *lhs, size_t req_order)
{
	/* LAB 1: your code here. */
	struct page_info *buddy;

	assert(req_order < BUDDY_MAX_ORDER && req_order >= 0);

	while( lhs->pp_order != req_order ){
		lhs->pp_order -= 1;
		buddy = pa2page( page2pa(lhs) + ( 1 << lhs->pp_order ) * PAGE_SIZE );
		buddy->pp_order = lhs->pp_order;
		buddy->pp_free = 1;
		// buddy->pp_ref = 0;
		list_push(&(page_free_list[buddy->pp_order]),&(buddy->pp_node));
	}

	return lhs;
}

/* Merges the buddy of the page with the page if the buddy is free to form
 * larger and larger free pages until either the maximum order is reached or
 * no free buddy is found.
 *
 * The algorithm to merge pages is as follows:
 *  - Given the page of order k, locate the page with the lowest address
 *    and its buddy of order k.
 *  - Check if both the page and the buddy are free and whether the order
 *    matches.
 *  - Remove the page and its buddy from the free list.
 *  - Increment the order of the page.
 *  - Repeat until the maximum order has been reached or until the buddy is not
 *    free.
 *
 * Returns the largest merged free page possible.
 */
struct page_info *buddy_merge(struct page_info *page)
{
	/* LAB 1: your code here. */
	physaddr_t buddy_pa;
	struct page_info *buddy_page = NULL,*tmp_page;
	struct list *tmp;

	while(page->pp_order < BUDDY_MAX_ORDER - 1){
		buddy_page = NULL;
		buddy_pa = page2pa(page) ^ ( (1 << (page->pp_order)) * PAGE_SIZE);
		/* Buddies can be found using only bit shifting, 
			which is much more performant than iterating 
			through the entire list
		*/
		list_foreach(&(page_free_list[page->pp_order]),tmp){
			tmp_page = container_of(tmp,struct page_info, pp_node);
			if(buddy_pa == page2pa(tmp_page)) {
				buddy_page = tmp_page;
				break;
			}
		}

		if( buddy_page && ( buddy_page->pp_order == page->pp_order ) ){
			page->pp_free = 0;
			buddy_page->pp_free = 0;
			list_remove(&(page->pp_node));
			list_remove(&(buddy_page->pp_node));
			page = (page2pa(page) < page2pa(buddy_page) ? page : buddy_page);
			page->pp_order++;
		} else break;
	}

	return page;
}

/* Given the order req_order, attempts to find a page of that order or a larger
 * order in the free list. In case the order of the free page is larger than the
 * requested order, the page is split down to the requested order using
 * buddy_split().
 *
 * Returns a page of the requested order or NULL if no such page can be found.
 */
struct page_info *buddy_find(size_t req_order)
{
	/* LAB 1: your code here. */
	unsigned order;
	struct page_info *ret;
	struct list *avail;

	for(order = req_order; order < BUDDY_MAX_ORDER; order++){
		/*While sanity checks are always a good idea, 
		  you should avoid iterating through the entire list. 
		  Imagine what would happen on a system with lots of RAM
		*/
		if( count_free_pages(order) ) break;
	}

	if( order >= BUDDY_MAX_ORDER ) return NULL;

	avail = list_pop(&page_free_list[order]);
	ret = container_of(avail,struct page_info,pp_node);
	if(order > req_order) {
		ret = buddy_split( ret, req_order );
	}
	ret->pp_order = req_order;
	ret->pp_free = 0;

	return ret;
}

/*
 * Allocates a physical page.
 *
 * if (alloc_flags & ALLOC_ZERO), fills the entire returned physical page with
 * '\0' bytes.
 * if (alloc_flags & ALLOC_HUGE), returns a huge physical 2M page.
 *
 * Beware: this function does NOT increment the reference count of the page -
 * this is the caller's responsibility.
 *
 * Returns NULL if out of free memory.
 *
 * Hint: use buddy_find() to find a free page of the right order.
 * Hint: use page2kva() and memset() to clear the page.
 */
struct page_info *page_alloc(int alloc_flags)
{
	/* LAB 1: your code here. */
	struct page_info *page;
	unsigned order = BUDDY_4K_PAGE;

	#ifdef BONUS_LAB1
	if(alloc_flags & ALLOC_HUGE) order = BUDDY_2M_PAGE;
	#endif
	spin_lock(&buddy_lock);
	page = buddy_find(order);

	if(!page){
		spin_unlock(&buddy_lock);
		return NULL;
	} 

	if( alloc_flags & ALLOC_ZERO ){
		memset(page2kva(page),'\0',PAGE_SIZE);
	}
	spin_unlock(&buddy_lock);
	return page;
}

/*
 * Return a page to the free list.
 * (This function should only be called when pp->pp_ref reaches 0.)
 *
 * Hint: mark the page as free and use buddy_merge() to merge the free page
 * with its buddies before returning the page to the free list.
 */
void page_free(struct page_info *pp)
{
	/* LAB 1: your code here. */
	// #ifdef BONUS_LAB1
	if(pp->pp_free == 1) panic("double free\n");
	
	unsigned n;
	for(n = 0; n < npages; n++){
		if( pp == pages + n) break;
	}
	/* if page not found in pages */
	if(n >= npages) panic("invalid free\n");
	// #endif
	#ifdef USE_BUDDY_LOCK
		spin_lock(&buddy_lock);
	#endif
	struct page_info *page;

	page = buddy_merge(pp);
	page->pp_free = 1;
	list_push(&(page_free_list[page->pp_order]),&(page->pp_node));
	#ifdef USE_BUDDY_LOCK
		spin_unlock(&buddy_lock);
	#endif
}

/*
 * Decrement the reference count on a page,
 * freeing it if there are no more refs.
 */
void page_decref(struct page_info *pp)
{
	if (--pp->pp_ref == 0) {
		page_free(pp);
	}
}

static int in_page_range(void *p)
{
	return ((uintptr_t)pages <= (uintptr_t)p &&
	        (uintptr_t)p < (uintptr_t)(pages + npages));
}

static void *update_ptr(void *p)
{
	if (!in_page_range(p))
		return p;

	return (void *)((uintptr_t)p + KPAGES - (uintptr_t)pages);
}

void buddy_migrate(void)
{
	struct page_info *page;
	struct list *node;
	size_t i;

	for (i = 0; i < npages; ++i) {
		page = pages + i;
		node = &page->pp_node;

		node->next = update_ptr(node->next);
		node->prev = update_ptr(node->prev);
	}

	for (i = 0; i < BUDDY_MAX_ORDER; ++i) {
		node = page_free_list + i;

		node->next = update_ptr(node->next);
		node->prev = update_ptr(node->prev);
	}

	pages = (struct page_info *)KPAGES;
}

int buddy_map_chunk(struct page_table *pml4, size_t index)
{
	struct page_info *page, *base;
	void *end;
	size_t nblocks = (1 << (12 + BUDDY_MAX_ORDER - 1)) / PAGE_SIZE;
	size_t nalloc = ROUNDUP(nblocks * sizeof *page, PAGE_SIZE) / PAGE_SIZE;
	size_t i;

	index = ROUNDDOWN(index, nblocks);
	base = pages + index;
	
	for (i = 0; i < nalloc; ++i) {
		page = page_alloc(ALLOC_ZERO);

		if (!page) {
			return -1;
		}

		if (page_insert(pml4, page, (char *)base + i * PAGE_SIZE,
		    PAGE_PRESENT | PAGE_WRITE | PAGE_NO_EXEC) < 0) {
			return -1;
		}
	}

	for (i = 0; i < nblocks; ++i) {
		page = base + i;
		list_init(&page->pp_node);
		list_init(&page->lru_node);
	}

	npages = index + nblocks;

	return 0;
}

