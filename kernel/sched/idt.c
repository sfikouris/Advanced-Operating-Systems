#include <assert.h>
#include <stdio.h>

#include <x86-64/asm.h>
#include <x86-64/gdt.h>
#include <x86-64/idt.h>

#include <kernel/acpi.h>
#include <kernel/sched/idt.h>
#include <kernel/monitor.h>
#include <kernel/sched/syscall.h>

#include <kernel/sched/task.h>
#include <kernel/vma/pfault.h>
#include <kernel/sched/sched.h>
#include <kernel/acpi/lapic.h>

static const char *int_names[256] = {
	[INT_DIVIDE] = "Divide-by-Zero Error Exception (#DE)",
	[INT_DEBUG] = "Debug (#DB)",
	[INT_NMI] = "Non-Maskable Interrupt",
	[INT_BREAK] = "Breakpoint (#BP)",
	[INT_OVERFLOW] = "Overflow (#OF)",
	[INT_BOUND] = "Bound Range (#BR)",
	[INT_INVALID_OP] = "Invalid Opcode (#UD)",
	[INT_DEVICE] = "Device Not Available (#NM)",
	[INT_DOUBLE_FAULT] = "Double Fault (#DF)",
	[INT_TSS] = "Invalid TSS (#TS)",
	[INT_NO_SEG_PRESENT] = "Segment Not Present (#NP)",
	[INT_SS] = "Stack (#SS)",
	[INT_GPF] = "General Protection (#GP)",
	[INT_PAGE_FAULT] = "Page Fault (#PF)",
	[INT_FPU] = "x86 FPU Floating-Point (#MF)",
	[INT_ALIGNMENT] = "Alignment Check (#AC)",
	[INT_MCE] = "Machine Check (#MC)",
	[INT_SIMD] = "SIMD Floating-Point (#XF)",
	[INT_SECURITY] = "Security (#SX)",
	[IRQ_TIMER] = "Hardware Interrupt (#HW)",
};

static struct idt_entry entries[256];
static struct idtr idtr = {
	.limit = sizeof(entries) - 1,
	.entries = entries,
};

static const char *get_int_name(unsigned int_no)
{
	if (!int_names[int_no])
		return "Unknown Interrupt";

	return int_names[int_no];
}

void print_int_frame(struct int_frame *frame)
{
	cprintf("INT frame at %p\n", frame);

	/* Print the interrupt number and the name. */
	cprintf(" INT %u: %s\n",
		frame->int_no,
		get_int_name(frame->int_no));

	/* Print the error code. */
	switch (frame->int_no) {
	case INT_PAGE_FAULT:
		cprintf(" CR2 %p\n", read_cr2());
		cprintf(" ERR 0x%016llx (%s, %s, %s)\n",
			frame->err_code,
			frame->err_code & 4 ? "user" : "kernel",
			frame->err_code & 2 ? "write" : "read",
			frame->err_code & 1 ? "protection" : "not present");
		break;
	default:
		cprintf(" ERR 0x%016llx\n", frame->err_code);
	}

	/* Print the general-purpose registers. */
	cprintf(" RAX 0x%016llx"
		" RCX 0x%016llx"
		" RDX 0x%016llx"
		" RBX 0x%016llx\n"
		" RSP 0x%016llx"
		" RBP 0x%016llx"
		" RSI 0x%016llx"
		" RDI 0x%016llx\n"
		" R8  0x%016llx"
		" R9  0x%016llx"
		" R10 0x%016llx"
		" R11 0x%016llx\n"
		" R12 0x%016llx"
		" R13 0x%016llx"
		" R14 0x%016llx"
		" R15 0x%016llx\n",
		frame->rax, frame->rcx, frame->rdx, frame->rbx,
		frame->rsp, frame->rbp, frame->rsi, frame->rdi,
		frame->r8,  frame->r9,  frame->r10, frame->r11,
		frame->r12, frame->r13, frame->r14, frame->r15);

	/* Print the IP, segment selectors and the RFLAGS register. */
	cprintf(" RIP 0x%016llx"
		" RFL 0x%016llx\n"
		" CS  0x%04x"
		"            "
		" DS  0x%04x"
		"            "
		" SS  0x%04x\n",
		frame->rip, frame->rflags,
		frame->cs, frame->ds, frame->ss);
}

/* Set up the interrupt handlers. */
void idt_init(void)
{
	/* LAB 3: your code here. */
    set_idt_entry(&entries[0], isr0, DPL3, GDT_KCODE);//
	set_idt_entry(&entries[1], isr1, DPL3, GDT_KCODE);//
	set_idt_entry(&entries[2], isr2, DPL3, GDT_KCODE);//
	set_idt_entry(&entries[3], isr3, DPL3, GDT_KCODE);//
	set_idt_entry(&entries[4], isr4, DPL3, GDT_KCODE);//
	set_idt_entry(&entries[5], isr5, DPL3, GDT_KCODE);//
	set_idt_entry(&entries[6], isr6, DPL3, GDT_KCODE);//
	set_idt_entry(&entries[7], isr7, DPL3, GDT_KCODE);
	set_idt_entry(&entries[8], isr8, DPL3, GDT_KCODE);//
	set_idt_entry(&entries[10], isr10, DPL3, GDT_KCODE);
	set_idt_entry(&entries[11], isr11, DPL3, GDT_KCODE);
	set_idt_entry(&entries[12], isr12, DPL3, GDT_KCODE);
	set_idt_entry(&entries[13], isr13, DPL3, GDT_KCODE);//
	set_idt_entry(&entries[14], isr14, DPL0, GDT_KCODE);//
	set_idt_entry(&entries[16], isr16, DPL3, GDT_KCODE);//
	set_idt_entry(&entries[17], isr17, DPL3, GDT_KCODE);
	set_idt_entry(&entries[18], isr18, DPL3, GDT_KCODE);
	set_idt_entry(&entries[19], isr19, DPL3, GDT_KCODE);
	set_idt_entry(&entries[30], isr30, DPL3, GDT_KCODE);
	set_idt_entry(&entries[32], isr32, DPL0, GDT_KCODE);
	set_idt_entry(&entries[128], isr128, DPL3, GDT_KCODE);//
	load_idt(&idtr);
}

void idt_init_mp(void)
{
	/* LAB 6: your code here. */
	load_idt(&idtr);
}

void int_dispatch(struct int_frame *frame)
{
	/* Handle processor exceptions:
	 *  - Fall through to the kernel monitor on a breakpoint.
	 *  - Dispatch page faults to page_fault_handler().
	 *  - Dispatch system calls to syscall().
	 */
	/* LAB 3: your code here. */
	switch (frame->int_no) {
		case INT_SYSCALL: 	
			frame->rax = syscall(frame->rdi, frame->rsi, frame->rdx, frame->rcx, frame->r8, frame->r9, frame->rbp);
			return;
		case INT_BREAK: 
			monitor(frame);
			return;
		case INT_PAGE_FAULT: 
			page_fault_handler(frame);
			return;
		case IRQ_TIMER:
			lapic_eoi();
			sched_yield();
	default: break;
	}

	/* Unexpected trap: The user process or the kernel has a bug. */
	print_int_frame(frame);

	if (frame->cs == GDT_KCODE) {
		panic("unhandled interrupt in kernel");
	} else {
		task_destroy(cur_task);
		return;
	}
}

void int_handler(struct int_frame *frame)
{
	/* The task may have set DF and some versions of GCC rely on DF being
	 * clear. */
	asm volatile("cld" ::: "cc");

	/* Check if interrupts are disabled.
	 * If this assertion fails, DO NOT be tempted to fix it by inserting a
	 * "cli" in the interrupt path.
	 */
	assert(!(read_rflags() & FLAGS_IF));

	// cprintf("Incoming INT frame at %p\n", frame);
	
	if ((frame->cs & 3) == 3) {
		/* Interrupt from user mode. */
		assert(cur_task);
		// if (cur_task->task_status == TASK_DYING) {
		// 	task_free(cur_task);
		// 	cur_task = NULL;
		// 	sched_yield();
		// }
		/* Copy interrupt frame (which is currently on the stack) into
		 * 'cur_task->task_frame', so that running the task will restart at
		 * the point of interrupt. */
		cur_task->task_frame = *frame;

		/* Avoid using the frame on the stack. */
		frame = &cur_task->task_frame;
	}

	/* Dispatch based on the type of interrupt that occurred. */
	int_dispatch(frame);

	/* Return to the current task, which should be running. */
	// task_run(cur_task);
	// if (cur_task && cur_task->task_status == TASK_RUNNING) {
	// 	task_run(cur_task);
	// } else {
	sched_yield();
	// }
}

void page_fault_handler(struct int_frame *frame)
{
	void *fault_va;
	unsigned perm = 0;
	int ret;

	/* Read the CR2 register to find the faulting address. */
	fault_va = (void *)read_cr2();

	/* Handle kernel-mode page faults. */
	/* LAB 3: your code here. */
	if( frame->cs == GDT_KCODE ){
		print_int_frame(frame);
		panic("kernel mode page fault %d\n",this_cpu->cpu_id);
	}

	/* We have already handled kernel-mode exceptions, so if we get here, the
	 * page fault has happened in user mode.
	 */
	if( (ret = task_page_fault_handler(cur_task, fault_va, perm | frame->err_code)) == 0) return;

	/* Destroy the task that caused the fault. */
	cprintf("[PID %5u] user fault va %p ip %p\n",
		cur_task->task_pid, fault_va, frame->rip);
	print_int_frame(frame);
	task_destroy(cur_task);
}

