/* SPDX-FileCopyrightText: 2026 Suderra OS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
ENTRY(_start)
SECTIONS
{
	. = 0x40080000;	/* RAM base of the QEMU virt machine + the arm64 text offset */
	.text : { KEEP(*(.text.head)) *(.text .text.*) }
	.rodata : { *(.rodata .rodata.*) }
	.data : { *(.data .data.*) }
	_edata = .;
	.bss : { *(.bss .bss.*) }
	_end = .;
	/* the image must start with the header: no build-id note in front of it */
	/DISCARD/ : { *(.note*) *(.eh_frame*) *(.comment*) }
}
