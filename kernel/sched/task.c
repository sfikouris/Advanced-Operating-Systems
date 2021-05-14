#include <error.h>
#include <string.h>
#include <paging.h>
#include <task.h>
#include <cpu.h>

#include <kernel/acpi.h>
#include <kernel/monitor.h>
#include <kernel/mem.h>
#include <kernel/sched.h>
#include <kernel/vma.h>
#include <kernel/dev/disk.h>

pid_t pid_max = 1 << 16;
struct task **tasks = (struct task **)PIDMAP_BASE;
size_t nuser_tasks = 0;
extern struct list runq;

/* Looks up the respective task for a given PID.
 * If check_perm is non-zero, this function checks if the PID maps to the
 * current task or if the current task is the parent of the task that the PID
 * maps to.
 */
struct task *pid2task(pid_t pid, int check_perm)
{
	struct task *task;
	
	/* PID 0 is the current task. */
	if (pid == 0) {
		return cur_task;
	}

	/* Limit the PID. */
	if (pid >= pid_max) {
		return NULL;
	}

	/* Look up the task in the PID map. */
	task = tasks[pid];

	/* No such mapping found. */
	if (!task) {
		return NULL;
	}

	/* If we don't have to do a permission check, we can simply return the
	 * task.
	 */
	if (!check_perm) {
		return task;
	}

	/* Check if the task is the current task or if the current task is the
	 * parent. If not, then the current task has insufficient permissions.
	 */
	if (task != cur_task && task->task_ppid != cur_task->task_pid) {
		return NULL;
	}

	return task;
}

void task_init(void)
{
	/* Allocate an array of pointers at PIDMAP_BASE to be able to map PIDs
	 * to tasks.
	 */
	/* LAB 3: your code here. */
	struct page_info *page = page_alloc(ALLOC_ZERO);

	assert(page);

	page_insert(kernel_pml4,page,(void*)PIDMAP_BASE, PAGE_PRESENT | PAGE_WRITE | PAGE_NO_EXEC);

	size_t n = PAGE_SIZE/sizeof(struct task*);

	for(size_t i = 0; i < n; ++i) tasks[i] = NULL;

}

/* Sets up the virtual address space for the task. */
static int task_setup_vas(struct task *task)
{
	struct page_info *page;

	spin_lock(&task->task_lock);
	/* Allocate a page for the page table. */
	page = page_alloc(ALLOC_ZERO);

	if (!page) {
		spin_unlock(&task->task_lock);
		return -ENOMEM;
	}

	++page->pp_ref;

	/* Now set task->task_pml4 and initialize the page table.
	 * Can you use kernel_pml4 as a template?
	 */

	/* LAB 3: your code here. */
	task->task_pml4 = page2kva(page); 
	memcpy( task->task_pml4, kernel_pml4, PAGE_SIZE );
	spin_unlock(&task->task_lock);

	return 0;
}

/* Allocates and initializes a new task.
 * On success, the new task is returned.
 */
struct task *task_alloc(pid_t ppid)
{
	struct task *task;
	pid_t pid;

	/* Allocate a new task struct. */
	task = kmalloc(sizeof *task);

	if (!task) {
		return NULL;
	}

	/* Set up the virtual address space for the task. */
	if (task_setup_vas(task) < 0) {
		kfree(task);
		return NULL;
	}

	/* Find a free PID for the task in the PID mapping and associate the
	 * task with that PID.
	 */
	for (pid = 1; pid < pid_max; ++pid) {
		if (!tasks[pid]) {
			tasks[pid] = task;
			task->task_pid = pid;
			break;
		}
	}

	/* We are out of PIDs. */
	if (pid == pid_max) {
		kfree(task);
		return NULL;
	}

	/* Set up the task. */
	task->task_ppid = ppid;
	task->task_type = TASK_TYPE_USER;
	task->task_status = TASK_RUNNABLE;
	task->task_runs = 0;
	
	list_init(&task->task_mmap);
	rb_init(&task->task_rb);
	list_init(&task->task_node);
	list_init(&task->task_child);
	list_init(&task->task_children);
	spin_init(&task->task_lock, "task_lock");
	
	memset(&task->task_frame, 0, sizeof task->task_frame);

	task->task_frame.ds = GDT_UDATA | 3;
	task->task_frame.ss = GDT_UDATA | 3;
	task->task_frame.rsp = USTACK_TOP;
	task->task_frame.cs = GDT_UCODE | 3;
	task->task_frame.rflags |= FLAGS_IF;

	/* You will set task->task_frame.rip later. */

	cprintf("[PID %5u] New task with PID %u\n",
	        cur_task ? cur_task->task_pid : 0, task->task_pid);

	return task;
}

struct task *kernel_task_alloc(pid_t ppid){
	struct task *kernel_task;
	struct page_info *page;

	struct task *task;
	pid_t pid;

	/* Allocate a new task struct. */
	task = kmalloc(sizeof *task);

	if (!task) {
		return NULL;
	}

	/* Set up the virtual address space for the task. */
	if (task_setup_vas(task) < 0) {
		kfree(task);
		return NULL;
	}

	/* Find a free PID for the task in the PID mapping and associate the
	 * task with that PID.
	 */
	for (pid = 1 << 8; pid < pid_max; ++pid) {
		if (!tasks[pid]) {
			tasks[pid] = task;
			task->task_pid = pid;
			break;
		}
	}

	/* We are out of PIDs. */
	if (pid == pid_max) {
		kfree(task);
		return NULL;
	}

	/* Set up the task. */
	task->task_ppid = ppid;
	task->task_type = TASK_TYPE_KERNEL;
	task->task_status = TASK_RUNNABLE;
	task->task_runs = 0;
	
	list_init(&task->task_mmap);
	rb_init(&task->task_rb);
	list_init(&task->task_node);
	list_init(&task->task_child);
	list_init(&task->task_children);
	spin_init(&task->task_lock, "task_lock");
	
	memset(&task->task_frame, 0, sizeof task->task_frame);

	task->task_frame.ds = GDT_KDATA;
	task->task_frame.ss = GDT_KDATA;
	task->task_frame.cs = GDT_KCODE;
	task->task_frame.rflags &= ~FLAGS_IF;
	
	// task->task_frame.rip = (uint64_t)mem_pressure;
	task->task_frame.rdi = task->task_pid;
	// kernel_task->task_frame.rsp = (uint64_t)USTACK_TOP + (kernel_task->task_pid * PAGE_SIZE ) + PAGE_SIZE; //
	task->task_frame.rsp = (uint64_t)USTACK_TOP + PAGE_SIZE; 

	page = page_alloc(ALLOC_ZERO);

	page_insert(task->task_pml4, page, (void *)USTACK_TOP, PAGE_PRESENT | PAGE_WRITE | PAGE_NO_EXEC);

	cprintf("[PID %5u] New kernel task with PID %u\n",
	        cur_task ? cur_task->task_pid : 0, task->task_pid);
	return task;
}

uint64_t sector_hashfunc(uint64_t addr){
	return (addr/599) % ALL_SECTORS;
}

uint64_t get_free_sector_index(void *addr){
	uint64_t index = sector_hashfunc((uint64_t)addr);

	for( uint64_t i = index; i < ALL_SECTORS; ++i ){
		if( !sectors[i].pva ) return i;
	}

	for( uint64_t i = 0; i < index; ++i ){
		if( !sectors[i].pva ) return i;
	}

	return -1;
}

void mem_pressure(){
	assert( !list_is_empty(&lru_list) );
	// spin_lock(&lru_lock);
	cprintf("MEMORY PRESSURE INVOKED\n");
	struct list *node,*next;
	struct page_info *page;
	uint64_t sector_index;
	physaddr_t *entry_store = NULL;
	int quarter = npages * 3 / 10;

	list_foreach_safe( &lru_list, node, next){

		page = container_of( node, struct page_info, lru_node);
		if( page->pp_ref > 1 ) continue;
		
		// cprintf(" %x, ", page->fault_addr);

		list_remove( &page->lru_node );
		--lru_len;

		sector_index = get_free_sector_index( page->fault_addr );
		if( sector_index == -1 ) panic("couldn't obtain a free sector ( mem_pressure() )\n");

		sectors[sector_index].pva = page->fault_addr;
		sectors[sector_index].id = sector_index * 8;

		disk_write(disks[1], page2kva(page), 8, sectors[sector_index].id);
		while (disk_poll(disks[1]) == -1);
		while (disk_write(disks[1], page2kva(page), 8, sectors[sector_index].id) == -1);

		page_lookup(page->task->task_pml4,page->fault_addr, &entry_store);
		memset( page2kva(page), 0, PAGE_SIZE);
		page_decref(page);
		*entry_store = (physaddr_t) NULL;
		tlb_invalidate(page->task->task_pml4,page->fault_addr);
		page->fault_addr = NULL;

		if( (--quarter) == 0 ) break;

	}
	// spin_unlock(&lru_lock);
	cprintf("task memory pressure done\n");
	// xchg(&boot_cpu->cpu_status, CPU_STARTED);
	sched_halt();

}


/* Sets up the initial program binary, stack and processor flags for a user
 * process.
 * This function is ONLY called during kernel initialization, before running
 * the first user-mode environment.
 *
 * This function loads all loadable segments from the ELF binary image into the
 * task's user memory, starting at the appropriate virtual addresses indicated
 * in the ELF program header.
 * At the same time it clears to zero any portions of these segments that are
 * marked in the program header as being mapped but not actually present in the
 * ELF file, i.e., the program's .bss section.
 *
 * All this is very similar to what our boot loader does, except the boot
 * loader also needs to read the code from disk. Take a look at boot/main.c to
 * get some ideas.
 *
 * Finally, this function maps one page for the program's initial stack.
 */
static void task_load_elf(struct task *task, uint8_t *binary)
{
	/* Hints:
	 * - Load each program segment into virtual memory at the address
	 *   specified in the ELF section header.
	 * - You should only load segments with type ELF_PROG_LOAD.
	 * - Each segment's virtual address can be found in p_va and its
	 *   size in memory can be found in p_memsz.
	 * - The p_filesz bytes from the ELF binary, starting at binary +
	 *   p_offset, should be copied to virtual address p_va.
	 * - Any remaining memory bytes should be zero.
	 * - Use populate_region() and protect_region().
	 * - Check for malicious input.
	 *
	 * Loading the segments is much simpler if you can move data directly
	 * into the virtual addresses stored in the ELF binary.
	 * So in which address space should we be operating during this
	 * function?
	 *
	 * You must also do something with the entry point of the program, to
	 * make sure that the task starts executing there.
	 */

	/* LAB 3: your code here. */
	struct elf *elf_hdr = (struct elf*)binary;
	struct elf_proghdr *prog_hdr,*eph;
	uint64_t flags = 0;
	char *region;
	struct vma *vma;
	
	prog_hdr = (struct elf_proghdr *)(((char *)elf_hdr) + elf_hdr->e_phoff);
	// load_pml4((struct page_table*)PADDR(task->task_pml4));

	eph = prog_hdr + elf_hdr->e_phnum;
	for (; prog_hdr < eph; prog_hdr++){
		flags = 0;
		if(prog_hdr->p_type == ELF_PROG_LOAD){

			if (prog_hdr->p_memsz == 0) continue;

			flags = VM_READ;
			flags |= (prog_hdr->p_flags & ELF_PROG_FLAG_WRITE) ? VM_WRITE : 0;
			flags |= (prog_hdr->p_flags & ELF_PROG_FLAG_EXEC)  ? VM_EXEC  : 0;

			if (prog_hdr->p_filesz) {
				switch (flags) {
					case VM_READ:
						region = ".rodata";
						break;
					case VM_READ | VM_WRITE:
						region = ".data";
						break;
					case VM_READ | VM_EXEC:
						region = ".text";
						break;
					default:
						panic("task_load_elf: corruppted flags.\n");
				}
				vma = add_executable_vma(task, region, (void*)prog_hdr->p_va, prog_hdr->p_memsz, flags, binary+prog_hdr->p_offset, prog_hdr->p_filesz);

			}else{
				vma = add_anonymous_vma(task, ".bss",( void*)prog_hdr->p_va, prog_hdr->p_memsz, flags);

			}

			if(!vma) panic("add_executable_vma failed\n");
		}
	}



	/* Now map one page for the program's initial stack at virtual address
	 * USTACK_TOP - PAGE_SIZE.
	 */

	/* LAB 3: your code here. (changed populate to add_vma in LAB4)*/
	flags = VM_READ | VM_WRITE;
	vma = add_anonymous_vma(task, "stack", (void *)(USTACK_TOP - PAGE_SIZE), PAGE_SIZE, flags);

	if(!vma) panic("add_executable_vma failed\n");
	
	task->task_frame.rip = elf_hdr->e_entry;
	task->task_frame.rsp = USTACK_TOP;

	load_pml4((struct page_table*)PADDR(kernel_pml4));

}

/* Allocates a new task with task_alloc(), loads the named ELF binary using
 * task_load_elf() and sets its task type.
 * If the task is a user task, increment the number of user tasks.
 * This function is ONLY called during kernel initialization, before running
 * the first user-mode task.
 * The new task's parent PID is set to 0.
 */
void task_create(uint8_t *binary, enum task_type type)
{
	/* LAB 3: your code here. */
	struct task *task = task_alloc(0);

	assert(task);
	
	spin_lock(&task->task_lock);
	task_load_elf(task,binary);
	spin_unlock(&task->task_lock);

	task->task_type = type;

	if(type == TASK_TYPE_USER) ++nuser_tasks; 

	/* LAB 5: your code here. */
	list_push(&(runq),&(task->task_node));
	
}

/* Free the task and all of the memory that is used by it.
 */
void task_free(struct task *task)
{
	struct task *waiting;

	/* LAB 5: your code here. */
	spin_lock(&task->task_lock);
	/* If we are freeing the current task, switch to the kernel_pml4
	 * before freeing the page tables, just in case the page gets re-used.
	 */	
	if (task == cur_task) {
		load_pml4((struct page_table *)PADDR(kernel_pml4));
	}

	/* Unmap the task from the PID map. */
	tasks[task->task_pid] = NULL;

	/* Unmap the user pages. */
	unmap_user_pages(task->task_pml4);

	/* Note the task's demise. */
	cprintf("[PID %5u] Freed task with PID %u\n", cur_task ? cur_task->task_pid : 0,
	    task->task_pid);

	/* Remove vmas */
	free_vmas(task);
	list_remove(&task->task_child);

	spin_unlock(&task->task_lock);
	/* Free the task. */
	kfree(task);
}

/* Frees the task. If the task is the currently running task, then this
 * function runs a new task (and does not return to the caller).
 */
void task_destroy(struct task *task)
{
	struct list *node = NULL;
	struct list *next = NULL;

	if (!list_is_empty(&task->task_children)) {
		list_foreach_safe(&task->task_children, node, next) {
			struct task *child = container_of(node, struct task, task_child);
			if (child->task_status == TASK_DYING) {
				list_remove(&child->task_child);
				task_free(child);
			}
		}
	}

	task_free(task);

	/* LAB 5: your code here. */
	if (cur_task == task) {
		cur_task = NULL;
		sched_yield();
	}
}

/*
 * Restores the register values in the trap frame with the iretq or sysretq
 * instruction. This exits the kernel and starts executing the code of some
 * task.
 *
 * This function does not return.
 */
void task_pop_frame(struct int_frame *frame)
{
	cur_task->task_cpunum = lapic_cpunum();
	switch (frame->int_no) {
#ifdef LAB3_SYSCALL
	case 0x80: sysret64(frame); break;
#endif
	default: iret64(frame); break;
	}

	panic("We should have gone back to userspace!");
}

/* Context switch from the current task to the provided task.
 * Note: if this is the first call to task_run(), cur_task is NULL.
 *
 * This function does not return.
 */
void task_run(struct task *task)
{
	/*
	 * Step 1: If this is a context switch (a new task is running):
	 *     1. Set the current task (if any) back to
	 *        TASK_RUNNABLE if it is TASK_RUNNING (think about
	 *        what other states it can be in),
	 *     2. Set 'cur_task' to the new task,
	 *     3. Set its status to TASK_RUNNING,
	 *     4. Update its 'task_runs' counter,
	 *     5. Use load_pml4() to switch to its address space.
	 * Step 2: Use task_pop_frame() to restore the task's
	 *     registers and drop into user mode in the
	 *     task.
	 *
	 * Hint: This function loads the new task's state from
	 *  e->task_frame.  Go back through the code you wrote above
	 *  and make sure you have set the relevant parts of
	 *  e->task_frame to sensible values.
	 */

	/* LAB 3: Your code here. */

	if( cur_task != task ){
		if(cur_task && cur_task->task_status == TASK_RUNNING){
			cur_task->task_status = TASK_RUNNABLE;
			list_push(&(this_cpu->runq),&(cur_task->task_node));
		}

		cur_task = task;
		cur_task->task_status = TASK_RUNNING;
		cur_task->task_runs++;

		load_pml4((struct page_table*)PADDR(cur_task->task_pml4));
	}
	// lapic_eoi();

	task_pop_frame(&cur_task->task_frame);

	// panic("task_run() not yet implemented");
}

