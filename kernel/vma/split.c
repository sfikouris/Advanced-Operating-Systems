#include <task.h>
#include <vma.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

/* Given a task and a VMA, this function splits the VMA at the given address
 * by setting the end address of original VMA to the given address and by
 * adding a new VMA with the given address as base.
 */
struct vma *split_vma(struct task *task, struct vma *lhs, void *addr)
{
	/* LAB 4: your code here. */
	if ( (lhs->vm_base == addr) || (lhs->vm_end==addr) ) return NULL;

	struct vma* n_vma = kmalloc(sizeof(struct vma));
	n_vma->vm_base = ROUNDDOWN(addr,PAGE_SIZE);
	n_vma->vm_end = ROUNDUP(lhs->vm_end,PAGE_SIZE);
	n_vma->vm_name = kmalloc(strlen(lhs->vm_name));
	memcpy(n_vma->vm_name,lhs->vm_name,strlen(lhs->vm_name));
	n_vma->vm_src = lhs->vm_src;
	n_vma->vm_len = lhs->vm_len;//shouldn't be half?
	n_vma->vm_flags = lhs->vm_flags;
	n_vma->vm_offset = (uintptr_t)addr & 0xfff;
	list_init(&n_vma->vm_mmap);

	lhs->vm_end = addr;//ROUNDDOWN?

	return (insert_vma(task,n_vma) < 0) ? NULL : n_vma;
}

/* Given a task and a VMA, this function first splits the VMA into a left-hand
 * and right-hand side at address base. Then this function splits the
 * right-hand side or the original VMA, if no split happened, into a left-hand
 * and a right-hand side. This function finally returns the right-hand side of
 * the first split or the original VMA.
 */
struct vma *split_vmas(struct task *task, struct vma *vma, void *base, size_t size)
{
	/* LAB 4: your code here. */
	struct vma *rhs = split_vma(task,vma,base);
	struct vma *tmp = (rhs) ?  rhs : vma;

	split_vma(task,tmp,tmp->vm_base + size);

	return tmp;
}

