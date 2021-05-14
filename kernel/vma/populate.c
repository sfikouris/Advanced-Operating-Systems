#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

extern int lru_len;
extern struct list lru_list;
extern struct spinlock lru_lock;

/* Checks the flags in udata against the flags of the VMA to check appropriate
 * permissions. If the permissions are all right, this function populates the
 * address range [base, base + size) with physical pages. If the VMA is backed
 * by an executable, the data is copied over. Then the protection of the
 * physical pages is adjusted to match the permissions of the VMA.
 */
int do_populate_vma(struct task *task, void *base, size_t size,
	struct vma *vma, void *udata)
{
	/* LAB 4: your code here. */
	struct page_info *page;
	int test_flags = VM_READ | (((*(int*)udata) & PAGE_WRITE) ? VM_WRITE : 0);
	
	
	if((vma->vm_flags & test_flags) == test_flags ){

		// spin_lock(&lru_lock);
		// check_mem_pressure();
		
		page = page_alloc(ALLOC_ZERO);
		if( !page ) panic("couldn't allocate page \n");

		list_push_left(&lru_list,&(page->lru_node));
		++lru_len;
		page->fault_addr = ROUNDDOWN( base, PAGE_SIZE );
		page->task = task;

		test_flags = PAGE_PRESENT | PAGE_USER
			| (vma->vm_flags & VM_WRITE ? PAGE_WRITE : 0) 
			| (vma->vm_flags & VM_EXEC ? 0 : PAGE_NO_EXEC);

		page_insert(task->task_pml4,page,ROUNDDOWN( base, PAGE_SIZE ),test_flags);
		
		if(vma->vm_src)	{
			if (base == vma->vm_base) {
                memcpy(page2kva(page) + vma->vm_offset, vma->vm_src, PAGE_SIZE - vma->vm_offset);
            } else {
                memcpy(page2kva(page), base - vma->vm_base - vma->vm_offset + vma->vm_src, PAGE_SIZE);
            }
		}

		// spin_unlock(&lru_lock);
		
		return 0;
	}

	return -1;
}

/* Populates the VMAs for the given address range [base, base + size) by
 * backing the VMAs with physical pages.
 */
int populate_vma_range(struct task *task, void *base, size_t size, int flags)
{
	return walk_vma_range(task, base, size, do_populate_vma, &flags);
}

