/*
 * SPDX-FileCopyrightText: 2026 Suderra OS contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The "kernel" of the U-Boot boot-chain test (tests/qemu/arm-fit-signature-boot.sh).
 *
 * U-Boot's bootm starts it like a Linux Image (arm64 Image header, x0 = the
 * device tree); it prints what U-Boot handed it, on the PL011 of the QEMU virt
 * machine, then powers the machine off. The test reads that line: the stub
 * having started proves bootm verified the FIT and jumped, and the bootargs it
 * prints are the kernel command line the real kernel would have received.
 *
 * Freestanding on purpose: no libc, no relocation, nothing the test environment
 * has to provide beyond a cross compiler.
 */

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long u64;

#define UART_DR (*(volatile u32 *)0x09000000UL)
#define UART_FR (*(volatile u32 *)0x09000018UL)
#define UART_FR_TXFF (1u << 5)

#define FDT_MAGIC 0xd00dfeedu
#define FDT_BEGIN_NODE 1u
#define FDT_END_NODE 2u
#define FDT_PROP 3u
#define FDT_NOP 4u
#define FDT_END 9u

static void put_char(char c)
{
	while (UART_FR & UART_FR_TXFF)
		;
	UART_DR = (u32)(u8)c;
}

static void put_str(const char *s)
{
	while (*s)
		put_char(*s++);
}

static u32 be32(const u8 *p)
{
	return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}

static int str_eq(const char *a, const char *b)
{
	while (*a && *a == *b) {
		a++;
		b++;
	}
	return *a == *b;
}

static u32 align4(u32 v)
{
	return (v + 3u) & ~3u;
}

static void power_off(void)
{
	/* PSCI SYSTEM_OFF; the conduit of the virt machine is hvc or smc. */
	register u64 x0 asm("x0") = 0x84000008UL;

	asm volatile("hvc #0" : "+r"(x0) : : "memory");
	asm volatile("smc #0" : "+r"(x0) : : "memory");
	for (;;)
		asm volatile("wfi");
}

void stub_main(const u8 *fdt)
{
	const u8 *st, *strs;
	u32 off = 0, depth = 0, in_chosen = 0, tok;
	int have_bootargs = 0, have_initrd = 0;

	put_str("SUDERRA-STUB: kernel started\n");
	if (be32(fdt) != FDT_MAGIC) {
		put_str("SUDERRA-STUB: no device tree\n");
		power_off();
	}
	st = fdt + be32(fdt + 8);
	strs = fdt + be32(fdt + 12);

	for (;;) {
		tok = be32(st + off);
		off += 4;
		if (tok == FDT_BEGIN_NODE) {
			const char *name = (const char *)(st + off);
			u32 n = 0;

			while (name[n])
				n++;
			off += align4(n + 1);
			depth++;
			if (depth == 2 && str_eq(name, "chosen"))
				in_chosen = 1;
		} else if (tok == FDT_END_NODE) {
			if (depth == 2)
				in_chosen = 0;
			depth--;
		} else if (tok == FDT_PROP) {
			u32 len = be32(st + off);
			u32 nameoff = be32(st + off + 4);
			const char *name = (const char *)(strs + nameoff);
			const u8 *val = st + off + 8;

			if (in_chosen && str_eq(name, "bootargs")) {
				put_str("SUDERRA-STUB: bootargs=[");
				put_str((const char *)val);
				put_str("]\n");
				have_bootargs = 1;
			}
			if (in_chosen && str_eq(name, "linux,initrd-start"))
				have_initrd = 1;
			off += 8 + align4(len);
		} else if (tok == FDT_NOP) {
			continue;
		} else {
			break; /* FDT_END or a damaged tree */
		}
	}
	if (!have_bootargs)
		put_str("SUDERRA-STUB: bootargs=<none>\n");
	put_str(have_initrd ? "SUDERRA-STUB: initrd=present\n"
			    : "SUDERRA-STUB: initrd=absent\n");
	put_str("SUDERRA-STUB: done\n");
	power_off();
}
