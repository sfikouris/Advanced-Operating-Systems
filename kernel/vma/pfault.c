#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>
#include <kernel/dev/disk.h>
#include <kernel/sched.h>

/* The big kernel lock */
struct spinlock lru_lock = {
	.name = "lru_lock"
};

int lru_len = 0;
struct list lru_list;
struct sectors *sectors = NULL;

void check_mem_pressure(void){
	// cprintf(" %d/%d \n",lru_len,npages);
	if( lru_len >= npages * 7 / 10){
		xchg(&(cpus[ncpus - 1].cpu_status), CPU_STARTED);
		// xchg(&this_cpu->cpu_status, CPU_HALTED);
        // while (this_cpu->cpu_status != CPU_STARTED);
	}
}

void sector_free(int sector_index){
	sectors[sector_index].pva = NULL;
	sectors[sector_index].id = 0;
}

int check_disk(void *fa){
	// spin_lock(&lru_lock);

	uint64_t index = sector_hashfunc((uint64_t)fa);
	struct page_info *page;

	// check_mem_pressure();
	
	for( uint64_t i = index; i < ALL_SECTORS; ++i ){
		if( !sectors[i].pva ) return -1;
		if( sectors[i].pva == fa )	return i;
	}

	for( uint64_t i = 0; i < index; ++i ){
		if( !sectors[i].pva ) return -1;
		if( sectors[i].pva == fa )	return i;
	}
	// spin_unlock(&lru_lock);
	
	return -1;
}

int read_sector(int sector_index, struct vma *vma){
	// spin_lock(&lru_lock);

	struct sectors sector = sectors[sector_index];
	struct page_info *page = page_alloc(ALLOC_ZERO);
	unsigned page_flags = 0;

	if(!page) panic("failed to allocate page ( read sector() )\n");

	disk_read(disks[1], page2kva(page), 8, sector.id);
	while (disk_poll(disks[1]) == -1);
	while (disk_read(disks[1], page2kva(page), 8, sector.id) == -1);

	list_push_left(&lru_list,&(page->lru_node));
	++lru_len;
	page->fault_addr = ROUNDDOWN( sector.pva, PAGE_SIZE );
	page->task = cur_task;

	page_flags = PAGE_PRESENT | PAGE_USER
		| (vma->vm_flags & VM_WRITE ? PAGE_WRITE : 0) 
		| (vma->vm_flags & VM_EXEC ? 0 : PAGE_NO_EXEC);

	page_insert(cur_task->task_pml4, page, ROUNDDOWN( sector.pva, PAGE_SIZE ), page_flags);

	sector_free(sector_index);

	// spin_unlock(&lru_lock);
	return 0;
}

/* Handles the page fault for a given task. */
int task_page_fault_handler(struct task *task, void *va, int flags)
{
	/* LAB 4: your code here. */
	struct list *ptr;
	struct page_info *page,*new_page;
	physaddr_t *entry_store = NULL;
	struct vma* vma;
	int sector_index;

	check_mem_pressure();

	if( !(flags & PAGE_PRESENT) ){
		list_foreach(&task->task_mmap,ptr){
			struct vma* vma = container_of(ptr,struct vma,vm_mmap);
			if( va >= vma->vm_base && va < vma->vm_end ){
				// check_mem_pressure();
				
				if( (sector_index = check_disk( ROUNDDOWN(va, PAGE_SIZE) )) != -1 ) 
					return read_sector( sector_index, vma );

				return populate_vma_range(task,ROUNDDOWN(va,PAGE_SIZE),PAGE_SIZE,flags);
			}
		}
	}
	
	/* LAB 5: your code here. */
	if( flags & PAGE_WRITE ){
        if( (page = page_lookup(task->task_pml4, (void *)((uintptr_t)va & ~0xfff), &entry_store)) ){
			vma = task_find_vma(task,va);

			if( !(vma->vm_flags & VM_WRITE) ) return -1;

			int page_flags = PAGE_WRITE | PAGE_PRESENT | PAGE_USER;
            page_flags |= vma->vm_flags & VM_EXEC ? 0 : PAGE_NO_EXEC;

			if( page->pp_ref == 1 ) *entry_store |= page_flags;
			else{
				--page->pp_ref;

				// check_mem_pressure();

				new_page = page_alloc(0);
				++new_page->pp_ref;
				memcpy(page2kva(new_page),page2kva(page), PAGE_SIZE);
				*entry_store = page2pa(new_page) | page_flags;
			}
			return 0;
		}

	}
	// cprintf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaHERE %d\n",flags & PAGE_PRESENT);
	return -1;
}

