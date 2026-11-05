/* SPDX-License-Identifier: GPL-2.0 */
	.section .text
	.globl _start
	.type _start, @function
_start:
	movl	$3, %eax		/* __NR_read */
	xorl	%ebx, %ebx		/* stdin */
	movl	$input, %ecx
	movl	$1, %edx
	int	$0x80
	cmpl	$1, %eax
	jne	.Lexit
	call	user_mem_trigger
.Lexit:
	movl	$1, %eax		/* __NR_exit */
	xorl	%ebx, %ebx
	int	$0x80
	.size _start, . - _start

	.globl user_mem_trigger
	.type user_mem_trigger, @function
user_mem_trigger:
	ret
	.size user_mem_trigger, . - user_mem_trigger

	.section .bss
	.align 4
input:
	.zero 4

	.section .note.GNU-stack,"",@progbits
