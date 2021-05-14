#include <cpu.h>
#include <error.h>
#include <list.h>

#include <kernel/console.h>
#include <kernel/mem.h>
#include <kernel/monitor.h>
#include <kernel/sched.h>
#include <kernel/vma.h>

extern struct list runq;

void add_whole_vma(struct task *task,struct vma* vma){
	add_executable_vma(task,vma->vm_name,vma->vm_base,vma->vm_end - vma->vm_base,
						vma->vm_flags,vma->vm_src,vma->vm_len);
}


/* Allocates a task struct for the child_task process and copies the register state,
 * the VMAs and the page tables. Once the child_task task has been set up, it is
 * added to the run queue.
 */
struct task *task_clone(struct task *task)
{
    /* LAB 5: your code here. */
    struct task *child_task;
    struct list *node, *next;
    struct vma *vma;
    struct page_info *page;
    void *base;  
    physaddr_t *entry_store;
    struct page_table *new_pml4,*pdpt,*new_pdpt,*pdir,*new_pdir,*pt,*new_pt;
    int int_pml4, int_pdpt, int_pdir;

    child_task = task_alloc(task->task_pid);
    memcpy(&(child_task->task_frame), &(task->task_frame),sizeof(struct int_frame));
    child_task->task_frame.rax = 0;
    list_foreach_safe(&(task->task_mmap), node, next) {
        vma = container_of(node, struct vma, vm_mmap);
        add_whole_vma(child_task, vma);
        for(base = vma->vm_base; base < vma->vm_end; base += PAGE_SIZE){
            if ( (page = page_lookup(task->task_pml4, base, &entry_store)) ){
                page->pp_ref++;
                *entry_store &= ~PAGE_WRITE;
                tlb_invalidate(task->task_pml4, base);
            }
        }        
    }

	check_mem_pressure();

    //copy page tables
    page = page_alloc(ALLOC_ZERO);
    if (!page) panic("Couldn't allocate new page\n");
    
    new_pml4 = (struct page_table *) page2kva(page);

    memcpy(new_pml4, kernel_pml4, PAGE_SIZE);
    for (int_pml4 = 0; int_pml4 < 256; int_pml4++) {
        if (task->task_pml4->entries[int_pml4] & PAGE_PRESENT) {
            page = page_alloc(ALLOC_ZERO);
            if (!page) panic("Couldn't allocate new page\n");

            new_pml4->entries[int_pml4] = page2pa(page) | (task->task_pml4->entries[int_pml4] & PAGE_MASK);
            pdpt = (struct page_table *)KADDR(task->task_pml4->entries[int_pml4] & ~PAGE_MASK);
            new_pdpt = (struct page_table *)KADDR(new_pml4->entries[int_pml4] & ~PAGE_MASK);

            for (int_pdpt = 0; int_pdpt < 512; int_pdpt++) {
                if (pdpt->entries[int_pdpt] & PAGE_PRESENT) {
                    page = page_alloc(ALLOC_ZERO);
                    if (!page) panic("Couldn't allocate new page\n");

                    new_pdpt->entries[int_pdpt] = page2pa(page) | (pdpt->entries[int_pdpt] & PAGE_MASK);
                    pdir = (struct page_table *)KADDR(pdpt->entries[int_pdpt] & ~PAGE_MASK);
                    new_pdir = (struct page_table *)KADDR(new_pdpt->entries[int_pdpt] & ~PAGE_MASK);

                    for (int_pdir = 0; int_pdir < 512; int_pdir++) {
                        if (pdir->entries[int_pdir] & PAGE_PRESENT) {
                            page = page_alloc(ALLOC_ZERO);
                            if (!page) panic("Couldn't allocate new page\n");

                            new_pdir->entries[int_pdir] = page2pa(page) | (pdir->entries[int_pdir] & PAGE_MASK);
                            pt = (struct page_table *)KADDR(pdir->entries[int_pdir] & ~PAGE_MASK);
                            new_pt = (struct page_table *)KADDR(new_pdir->entries[int_pdir] & ~PAGE_MASK);

                            memcpy(new_pt, pt, PAGE_SIZE);
                        }
                    }
                }
            }
        }
    }

    child_task->task_pml4 = new_pml4;
    list_push(&runq, &child_task->task_node);
    return child_task;
}

pid_t sys_fork(void)
{
    /* LAB 5: your code here. */
    struct task *child_task = task_clone(cur_task);
    list_push(&cur_task->task_children, &child_task->task_child);
    return child_task->task_pid;
}

