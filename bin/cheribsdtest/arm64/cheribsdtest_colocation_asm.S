/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kian Cross
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency / Air Force Research Laboratory (DARPA/AFRL) Contract
 * No. FA8750-24-C-B047 ("DEC"), with additional support from a grant
 * from Google, Inc., and the Jesus College Embiricos Trust Scholarship.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Assembly helpers for the colocation register tests.
 *
 * Each helper saves the caller's callee-saved registers on entry and
 * restores them on exit.  It stores the registers to values[] before that
 * restore, so that values[] holds what the call left in them and not the
 * caller's values.
 */

#include <machine/asm.h>
#include <sys/elf_common.h>

/*
 * Stack frame of the GP helpers, from sp upwards:
 *
 *   SCRATCH_SIZE bytes	send and receive buffer for the call
 *   REG_WIDTH bytes	saved link register
 *   REG_WIDTH bytes	saved values pointer
 *   the rest		saved callee-saved registers of the caller
 */

#define	SCRATCH_SIZE		16
#if SCRATCH_SIZE != 16
#error "one 16-byte stp zeroes the scratch buffer"
#endif

#define	SAVED_LR_OFF		SCRATCH_SIZE
#define	SAVED_VALUES_OFF	(SCRATCH_SIZE + REG_WIDTH)
#define	SAVED_REGS_OFF		(SCRATCH_SIZE + 2 * REG_WIDTH)

#define	GP_SAVE_SIZE		(10 * REG_WIDTH)	/* c19-c28 */

#define	GP_FRAME_SIZE		(SAVED_REGS_OFF + GP_SAVE_SIZE)

/*
 * ssize_t cocall_with_gp_markers(void *target,
 *     void * const *markers, void **values);
 *
 * Loads markers[0..9] into c19-c28, calls cocall() with target, and
 * stores c19-c28 to values[0..9].  Returns what cocall() returns.
 */
ENTRY(cocall_with_gp_markers)
	sub	REGN(sp), REGN(sp), #GP_FRAME_SIZE
	stp	xzr, xzr, [REGN(sp)]	/* send no stale stack data */
	str	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	str	REG(2), [REGN(sp), #SAVED_VALUES_OFF]

	stp	REG(19), REG(20), [REGN(sp), #SAVED_REGS_OFF]
	stp	REG(21), REG(22), [REGN(sp), #(SAVED_REGS_OFF + 2 * REG_WIDTH)]
	stp	REG(23), REG(24), [REGN(sp), #(SAVED_REGS_OFF + 4 * REG_WIDTH)]
	stp	REG(25), REG(26), [REGN(sp), #(SAVED_REGS_OFF + 6 * REG_WIDTH)]
	stp	REG(27), REG(28), [REGN(sp), #(SAVED_REGS_OFF + 8 * REG_WIDTH)]

	ldp	REG(19), REG(20), [REG(1)]
	ldp	REG(21), REG(22), [REG(1), #(2 * REG_WIDTH)]
	ldp	REG(23), REG(24), [REG(1), #(4 * REG_WIDTH)]
	ldp	REG(25), REG(26), [REG(1), #(6 * REG_WIDTH)]
	ldp	REG(27), REG(28), [REG(1), #(8 * REG_WIDTH)]

	/* cocall(target, scratch, SCRATCH_SIZE, scratch, SCRATCH_SIZE) */
	mov	REG(1), REGN(sp)
	mov	x2, #SCRATCH_SIZE
	mov	REG(3), REGN(sp)
	mov	x4, #SCRATCH_SIZE
	bl	cocall

	/* Store c19-c28 to values before restoring the caller's c19-c28. */
	ldr	REG(9), [REGN(sp), #SAVED_VALUES_OFF]
	stp	REG(19), REG(20), [REG(9)]
	stp	REG(21), REG(22), [REG(9), #(2 * REG_WIDTH)]
	stp	REG(23), REG(24), [REG(9), #(4 * REG_WIDTH)]
	stp	REG(25), REG(26), [REG(9), #(6 * REG_WIDTH)]
	stp	REG(27), REG(28), [REG(9), #(8 * REG_WIDTH)]

	ldp	REG(19), REG(20), [REGN(sp), #SAVED_REGS_OFF]
	ldp	REG(21), REG(22), [REGN(sp), #(SAVED_REGS_OFF + 2 * REG_WIDTH)]
	ldp	REG(23), REG(24), [REGN(sp), #(SAVED_REGS_OFF + 4 * REG_WIDTH)]
	ldp	REG(25), REG(26), [REGN(sp), #(SAVED_REGS_OFF + 6 * REG_WIDTH)]
	ldp	REG(27), REG(28), [REGN(sp), #(SAVED_REGS_OFF + 8 * REG_WIDTH)]

	ldr	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	add	REGN(sp), REGN(sp), #GP_FRAME_SIZE

	RETURN
END(cocall_with_gp_markers)

/*
 * ssize_t coaccept_with_gp_markers(void *cookiep,
 *     void * const *markers, void **values);
 *
 * Loads markers[0..9] into c19-c28, calls coaccept() with cookiep, and
 * stores c19-c28 to values[0..9] when coaccept() returns.  Returns what
 * coaccept() returns.
 */
ENTRY(coaccept_with_gp_markers)
	sub	REGN(sp), REGN(sp), #GP_FRAME_SIZE
	str	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	str	REG(2), [REGN(sp), #SAVED_VALUES_OFF]

	stp	REG(19), REG(20), [REGN(sp), #SAVED_REGS_OFF]
	stp	REG(21), REG(22), [REGN(sp), #(SAVED_REGS_OFF + 2 * REG_WIDTH)]
	stp	REG(23), REG(24), [REGN(sp), #(SAVED_REGS_OFF + 4 * REG_WIDTH)]
	stp	REG(25), REG(26), [REGN(sp), #(SAVED_REGS_OFF + 6 * REG_WIDTH)]
	stp	REG(27), REG(28), [REGN(sp), #(SAVED_REGS_OFF + 8 * REG_WIDTH)]

	ldp	REG(19), REG(20), [REG(1)]
	ldp	REG(21), REG(22), [REG(1), #(2 * REG_WIDTH)]
	ldp	REG(23), REG(24), [REG(1), #(4 * REG_WIDTH)]
	ldp	REG(25), REG(26), [REG(1), #(6 * REG_WIDTH)]
	ldp	REG(27), REG(28), [REG(1), #(8 * REG_WIDTH)]

	/* coaccept(cookiep, scratch, SCRATCH_SIZE, scratch, SCRATCH_SIZE) */
	mov	REG(1), REGN(sp)
	mov	x2, #SCRATCH_SIZE
	mov	REG(3), REGN(sp)
	mov	x4, #SCRATCH_SIZE
	bl	coaccept

	/* Store c19-c28 to values before restoring the caller's c19-c28. */
	ldr	REG(9), [REGN(sp), #SAVED_VALUES_OFF]
	stp	REG(19), REG(20), [REG(9)]
	stp	REG(21), REG(22), [REG(9), #(2 * REG_WIDTH)]
	stp	REG(23), REG(24), [REG(9), #(4 * REG_WIDTH)]
	stp	REG(25), REG(26), [REG(9), #(6 * REG_WIDTH)]
	stp	REG(27), REG(28), [REG(9), #(8 * REG_WIDTH)]

	ldp	REG(19), REG(20), [REGN(sp), #SAVED_REGS_OFF]
	ldp	REG(21), REG(22), [REGN(sp), #(SAVED_REGS_OFF + 2 * REG_WIDTH)]
	ldp	REG(23), REG(24), [REGN(sp), #(SAVED_REGS_OFF + 4 * REG_WIDTH)]
	ldp	REG(25), REG(26), [REGN(sp), #(SAVED_REGS_OFF + 6 * REG_WIDTH)]
	ldp	REG(27), REG(28), [REGN(sp), #(SAVED_REGS_OFF + 8 * REG_WIDTH)]

	ldr	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	add	REGN(sp), REGN(sp), #GP_FRAME_SIZE

	RETURN
END(coaccept_with_gp_markers)

GNU_PROPERTY_AARCH64_FEATURE_1_NOTE(GNU_PROPERTY_AARCH64_FEATURE_1_VAL)
