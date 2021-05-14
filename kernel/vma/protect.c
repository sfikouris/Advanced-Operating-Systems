#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

/* Changes the protection flags of the given VMA. Does nothing if the flags
 * would remain the same. Splits up the VMA into the address range
 * [base, base + size) and changes the protection of the physical pages backing
 * the VMA. Then attempts to merge the VMAs in case the protection became the
 * same as that of any of the adjacent VMAs.
 */
int do_protect_vma(struct task *task, void *base, size_t size, struct vma *vma,
	void *udata)
{
	/* LAB 4 (bonus): your code here. */
	int flags = *(int *)udata;
	int page_flags;
 	struct vma *s_vma;
	physaddr_t *entry_store = NULL;

    if ( flags == vma->vm_flags ) {
        return 0;
    }

    if ( flags && !(flags & VM_READ) ){
		return -1;
    }

    page_flags = PAGE_PRESENT;
    page_flags |= flags & VM_WRITE ? PAGE_WRITE : 0;
    page_flags |= flags & VM_EXEC ? 0 : PAGE_NO_EXEC;

   	s_vma = split_vmas(task, vma, base, size);

    s_vma->vm_flags = flags;

    if( page_lookup(task->task_pml4, base, &entry_store) ){
        protect_region(task->task_pml4, base, size, page_flags);
    }

    merge_vmas(task, s_vma);
	return 0;
}

/* Changes the protection flags of the VMAs for the given address range
 * [base, base + size).
 */
int protect_vma_range(struct task *task, void *base, size_t size, int flags)
{
	return walk_vma_range(task, base, size, do_protect_vma, &flags);
}

