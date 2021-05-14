.section .text

#include <x86-64/gdt.h>
#include <x86-64/idt.h>
#include <x86-64/memory.h>

#include <cpu.h>

.macro ISR_NOERRCODE int_no
.global isr\int_no
isr\int_no:
	pushq $0
	pushq $\int_no
	jmp isr_common_stub
.endm

.macro ISR_ERRCODE int_no
.global isr\int_no
isr\int_no:
	pushq $\int_no
	jmp isr_common_stub
.endm

ISR_NOERRCODE 0
ISR_NOERRCODE 1
ISR_NOERRCODE 2
ISR_NOERRCODE 3
ISR_NOERRCODE 4
ISR_NOERRCODE 5
ISR_NOERRCODE 6
ISR_NOERRCODE 7
ISR_ERRCODE   8
ISR_ERRCODE   10
ISR_ERRCODE   11
ISR_ERRCODE   12
ISR_ERRCODE   13
ISR_ERRCODE   14
ISR_NOERRCODE 16
ISR_ERRCODE   17
ISR_NOERRCODE 18
ISR_NOERRCODE 19
ISR_NOERRCODE 30
ISR_NOERRCODE 32
ISR_NOERRCODE 128

isr_common_stub:
	/* LAB 3: your code here. */
	/* Save the register state on the stack. */
	pushq %rax
	pushq %rcx
	pushq %rdx
	pushq %rbx
	pushq %rbp
	pushq %rsi
	pushq %rdi
	pushq %r8
	pushq %r9
	pushq %r10
	pushq %r11
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
	movq %ds, %rax
	pushq %rax

	/* Recover the segments. */
	mov $GDT_KDATA, %ax
	mov %ax, %ds
	mov %ax, %es

	/* Jump to the generic interrupt handler. */
	movq %rsp, %rdi
	jmp int_handler

.global syscall64
syscall64:
	/* LAB 3: your code here. */
	/* Store the userspace stack pointer in the per-cpu struct. */

	/* Load the kernel stack pointer from the per-cpu struct. */

	/* Store the register state into the per-cpu struct. */

	/* Jump to the system call handler. */
	movq %r10, %rcx
	pushq %rbp
	pushq $0
	jmp syscall_handler

.global iret64
iret64:
	/* LAB 3: your code here. */
	/* Restore the register state. */
	pushq 8*22(%rdi)
	pushq 8*21(%rdi)
	pushq 8*20(%rdi)
	pushq 8*19(%rdi)
	pushq 8*18(%rdi)

	movq 8*15(%rdi), %rax
	movq 8*14(%rdi), %rcx
	movq 8*13(%rdi), %rdx
	movq 8*12(%rdi), %rbx
	movq 8*11(%rdi), %rbp
	movq 8*10(%rdi), %rsi
	movq 8*8(%rdi), %r8
	movq 8*7(%rdi), %r9
	movq 8*6(%rdi), %r10
	movq 8*5(%rdi), %r11
	movq 8*4(%rdi), %r12
	movq 8*3(%rdi), %r13
	movq 8*2(%rdi), %r14
	movq 8*1(%rdi), %r15
	mov 8*0(%rdi), %ds
	movq 8*9(%rdi), %rdi

	/* Return from the interrupt. */
	//addq $16, %rsp
	iretq

.global sysret64
sysret64:
	/* LAB 3: your code here. */
	/* Recover the register state. */

	/* Return from the system call. */
	sysretq

