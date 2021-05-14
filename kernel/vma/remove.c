#include <task.h>
#include <vma.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

/* Removes the given VMA from the given task. */
void remove_vma(struct task *task, struct vma *vma)
{
	if (!task || !vma) {
		return;
	}

	rb_remove(&task->task_rb, &vma->vm_rb);
	rb_node_init(&vma->vm_rb);
	list_remove(&vma->vm_mmap);
}

/* Frees all the VMAs for the given task. */
void free_vmas(struct task *task)
{
	/* LAB 4: your code here. */
	struct list *ptr = list_pop(&task->task_mmap);
	struct vma *vma;
	while(ptr){
		vma = container_of(ptr,struct vma,vm_mmap);
		remove_vma(task,vma);
		kfree(vma);
		ptr = list_pop(&task->task_mmap);
	}
}

/* Splits the VMA into the address range [base, base + size) and removes the
 * resulting VMA and any physical pages that back the VMA.
 */
int do_remove_vma(struct task *task, void *base, size_t size, struct vma *vma,
	void *udata)
{
	/* LAB 4: your code here. */
	struct vma *r_vma;
	struct page_info *page;
	physaddr_t *entry_store = NULL;
	
	r_vma = split_vmas(task, vma, base, size);
	page = page_lookup(task->task_pml4,r_vma->vm_base,&entry_store);

	if(entry_store && *entry_store){
		page_decref(page);
		tlb_invalidate(task->task_pml4,base);
		*entry_store = (physaddr_t)NULL;
	}

	remove_vma(task,r_vma);
	return 0;
}

/* Removes the VMAs and any physical pages backing those VMAs for the given
 * address range [base, base + size).
 */
int remove_vma_range(struct task *task, void *base, size_t size)
{
	return walk_vma_range(task, base, size, do_remove_vma, NULL);
}

/* Removes any non-dirty physical pages for the given address range
 * [base, base + size) within the VMA.
 */
int do_unmap_vma(struct task *task, void *base, size_t size, struct vma *vma,
	void *udata)
{
	/* LAB 4: your code here. */
	struct page_info *page;
	physaddr_t *entry_store = NULL;
	
	page = page_lookup(task->task_pml4,vma->vm_base,&entry_store);
	
	if( entry_store && (*entry_store & PAGE_DIRTY) ){
		page_decref(page);
		tlb_invalidate(task->task_pml4,base);
		*entry_store = (physaddr_t)NULL;
	}

	return 0;
}

/* Removes any non-dirty physical pages within the address range
 * [base, base + size).
 */
int unmap_vma_range(struct task *task, void *base, size_t size)
{
	return walk_vma_range(task, base, size, do_unmap_vma, NULL);
}

