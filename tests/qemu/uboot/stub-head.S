/*
 * SPDX-FileCopyrightText: 2026 Suderra OS contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * arm64 Image header (Documentation/arch/arm64/booting.rst) in front of the
 * stub kernel, so that U-Boot's bootm accepts it as a Linux kernel image.
 */
	.section .text.head, "ax"
	.globl _start
_start:
	b	start			/* code0 */
	.long	0			/* code1 */
	.quad	0			/* text_offset: the FIT's load address rules */
	.quad	_end - _start		/* image_size */
	.quad	0x2			/* flags: little endian, 4K pages */
	.quad	0			/* res2 */
	.quad	0			/* res3 */
	.quad	0			/* res4 */
	.ascii	"ARM\x64"		/* magic */
	.long	0			/* res5 */
start:
	ldr	x1, =stack_top
	mov	sp, x1
	bl	stub_main		/* x0 still holds the device tree */
1:	wfi
	b	1b

	.section .bss
	.balign 16
	.skip	4096
stack_top:
