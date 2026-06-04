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

#include "cheribsdtest_colocation_asm.h"

/*
 * Stack frame of the GP and FP helpers, from sp upwards:
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

#define	Q_WIDTH			16	/* bytes in a q register */

#define	GP_SAVE_SIZE		(10 * REG_WIDTH)	/* c19-c28 */
#define	FP_SAVE_SIZE		(8 * Q_WIDTH)		/* q8-q15 */

#define	GP_FRAME_SIZE		(SAVED_REGS_OFF + GP_SAVE_SIZE)
#define	FP_FRAME_SIZE		(SAVED_REGS_OFF + FP_SAVE_SIZE)

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
 * ssize_t cocall_with_fp_markers(void *target,
 *     const struct fp_q_value *markers, struct fp_q_value *values);
 *
 * Loads markers[0..7] into q8-q15, calls cocall() with target, and
 * stores q8-q15 to values[0..7].  Returns what cocall() returns.
 */
ENTRY(cocall_with_fp_markers)
	sub	REGN(sp), REGN(sp), #FP_FRAME_SIZE
	stp	xzr, xzr, [REGN(sp)]	/* send no stale stack data */
	str	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	str	REG(2), [REGN(sp), #SAVED_VALUES_OFF]

	stp	q8,  q9,  [REGN(sp), #SAVED_REGS_OFF]
	stp	q10, q11, [REGN(sp), #(SAVED_REGS_OFF + 2 * Q_WIDTH)]
	stp	q12, q13, [REGN(sp), #(SAVED_REGS_OFF + 4 * Q_WIDTH)]
	stp	q14, q15, [REGN(sp), #(SAVED_REGS_OFF + 6 * Q_WIDTH)]

	ldp	q8,  q9,  [REG(1)]
	ldp	q10, q11, [REG(1), #(2 * Q_WIDTH)]
	ldp	q12, q13, [REG(1), #(4 * Q_WIDTH)]
	ldp	q14, q15, [REG(1), #(6 * Q_WIDTH)]

	/* cocall(target, scratch, SCRATCH_SIZE, scratch, SCRATCH_SIZE) */
	mov	REG(1), REGN(sp)
	mov	x2, #SCRATCH_SIZE
	mov	REG(3), REGN(sp)
	mov	x4, #SCRATCH_SIZE
	bl	cocall

	/* Store q8-q15 to values before restoring the caller's q8-q15. */
	ldr	REG(9), [REGN(sp), #SAVED_VALUES_OFF]
	stp	q8,  q9,  [REG(9)]
	stp	q10, q11, [REG(9), #(2 * Q_WIDTH)]
	stp	q12, q13, [REG(9), #(4 * Q_WIDTH)]
	stp	q14, q15, [REG(9), #(6 * Q_WIDTH)]

	ldp	q8,  q9,  [REGN(sp), #SAVED_REGS_OFF]
	ldp	q10, q11, [REGN(sp), #(SAVED_REGS_OFF + 2 * Q_WIDTH)]
	ldp	q12, q13, [REGN(sp), #(SAVED_REGS_OFF + 4 * Q_WIDTH)]
	ldp	q14, q15, [REGN(sp), #(SAVED_REGS_OFF + 6 * Q_WIDTH)]

	ldr	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	add	REGN(sp), REGN(sp), #FP_FRAME_SIZE

	RETURN
END(cocall_with_fp_markers)

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

/*
 * ssize_t coaccept_with_fp_markers(void *cookiep,
 *     const struct fp_q_value *markers, struct fp_q_value *values);
 *
 * Loads markers[0..7] into q8-q15, calls coaccept() with cookiep, and
 * stores q8-q15 to values[0..7] when coaccept() returns.  Returns what
 * coaccept() returns.
 */
ENTRY(coaccept_with_fp_markers)
	sub	REGN(sp), REGN(sp), #FP_FRAME_SIZE
	str	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	str	REG(2), [REGN(sp), #SAVED_VALUES_OFF]

	stp	q8,  q9,  [REGN(sp), #SAVED_REGS_OFF]
	stp	q10, q11, [REGN(sp), #(SAVED_REGS_OFF + 2 * Q_WIDTH)]
	stp	q12, q13, [REGN(sp), #(SAVED_REGS_OFF + 4 * Q_WIDTH)]
	stp	q14, q15, [REGN(sp), #(SAVED_REGS_OFF + 6 * Q_WIDTH)]

	ldp	q8,  q9,  [REG(1)]
	ldp	q10, q11, [REG(1), #(2 * Q_WIDTH)]
	ldp	q12, q13, [REG(1), #(4 * Q_WIDTH)]
	ldp	q14, q15, [REG(1), #(6 * Q_WIDTH)]

	/* coaccept(cookiep, scratch, SCRATCH_SIZE, scratch, SCRATCH_SIZE) */
	mov	REG(1), REGN(sp)
	mov	x2, #SCRATCH_SIZE
	mov	REG(3), REGN(sp)
	mov	x4, #SCRATCH_SIZE
	bl	coaccept

	/* Store q8-q15 to values before restoring the caller's q8-q15. */
	ldr	REG(9), [REGN(sp), #SAVED_VALUES_OFF]
	stp	q8,  q9,  [REG(9)]
	stp	q10, q11, [REG(9), #(2 * Q_WIDTH)]
	stp	q12, q13, [REG(9), #(4 * Q_WIDTH)]
	stp	q14, q15, [REG(9), #(6 * Q_WIDTH)]

	ldp	q8,  q9,  [REGN(sp), #SAVED_REGS_OFF]
	ldp	q10, q11, [REGN(sp), #(SAVED_REGS_OFF + 2 * Q_WIDTH)]
	ldp	q12, q13, [REGN(sp), #(SAVED_REGS_OFF + 4 * Q_WIDTH)]
	ldp	q14, q15, [REGN(sp), #(SAVED_REGS_OFF + 6 * Q_WIDTH)]

	ldr	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	add	REGN(sp), REGN(sp), #FP_FRAME_SIZE

	RETURN
END(coaccept_with_fp_markers)

/*
 * The direct helper's frame starts like the others.  Its saved registers
 * are the caller's c19-c28, q8-q15, c29, CTPIDR_EL0, FPCR, and FPSR: it
 * loads markers into all of them but c29, which blrs overwrites with the
 * unsealed data capability.
 */
#define	DIRECT_GP_OFF		SAVED_REGS_OFF
#define	DIRECT_FP_OFF		(DIRECT_GP_OFF + GP_SAVE_SIZE)
#define	DIRECT_C29_OFF		(DIRECT_FP_OFF + FP_SAVE_SIZE)
#define	DIRECT_CTPIDR_OFF	(DIRECT_C29_OFF + REG_WIDTH)
#define	DIRECT_FPCR_OFF		(DIRECT_CTPIDR_OFF + REG_WIDTH)
#define	DIRECT_FPSR_OFF		(DIRECT_FPCR_OFF + 8)
#define	DIRECT_FRAME_SIZE	(DIRECT_FPSR_OFF + 8)

/*
 * ssize_t enter_switcher_with_markers(void *code, void *data,
 *     void *target_or_cookiep, const struct switcher_regset *markers,
 *     struct switcher_regset *values);
 *
 * Loads markers into c19-c28, q8-q15, FPCR, FPSR, and CTPIDR_EL0, enters
 * the switcher through the sealed pair code and data, and stores those
 * registers to values when the switcher returns.  The pair comes from
 * _cosetup() and picks the direction: with a cocall pair,
 * target_or_cookiep is the callee; with a coaccept pair, it is coaccept()'s
 * cookiep argument, where the switcher stores a value identifying the
 * caller (the tests pass NULL).  Returns the length received, or a negated
 * errno.
 *
 * CTPIDR_EL0 is the TLS pointer, so no C code may run while it holds a
 * marker.  The helper puts back the real CTPIDR_EL0, FPCR, and FPSR
 * before it returns.
 */
ENTRY(enter_switcher_with_markers)
	sub	REGN(sp), REGN(sp), #DIRECT_FRAME_SIZE
	stp	xzr, xzr, [REGN(sp)]	/* send no stale stack data */
	str	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	str	REG(4), [REGN(sp), #SAVED_VALUES_OFF]

	stp	REG(19), REG(20), [REGN(sp), #DIRECT_GP_OFF]
	stp	REG(21), REG(22), [REGN(sp), #(DIRECT_GP_OFF + 2 * REG_WIDTH)]
	stp	REG(23), REG(24), [REGN(sp), #(DIRECT_GP_OFF + 4 * REG_WIDTH)]
	stp	REG(25), REG(26), [REGN(sp), #(DIRECT_GP_OFF + 6 * REG_WIDTH)]
	stp	REG(27), REG(28), [REGN(sp), #(DIRECT_GP_OFF + 8 * REG_WIDTH)]

	stp	q8,  q9,  [REGN(sp), #DIRECT_FP_OFF]
	stp	q10, q11, [REGN(sp), #(DIRECT_FP_OFF + 2 * Q_WIDTH)]
	stp	q12, q13, [REGN(sp), #(DIRECT_FP_OFF + 4 * Q_WIDTH)]
	stp	q14, q15, [REGN(sp), #(DIRECT_FP_OFF + 6 * Q_WIDTH)]

	str	REG(29), [REGN(sp), #DIRECT_C29_OFF]
	mrs	REG(10), ctpidr_el0
	str	REG(10), [REGN(sp), #DIRECT_CTPIDR_OFF]
	mrs	x10, fpcr
	str	x10, [REGN(sp), #DIRECT_FPCR_OFF]
	mrs	x10, fpsr
	str	x10, [REGN(sp), #DIRECT_FPSR_OFF]

	ldp	REG(19), REG(20), [REG(3), #REGSET_GP_OFF]
	ldp	REG(21), REG(22), [REG(3), #(REGSET_GP_OFF + 2 * REG_WIDTH)]
	ldp	REG(23), REG(24), [REG(3), #(REGSET_GP_OFF + 4 * REG_WIDTH)]
	ldp	REG(25), REG(26), [REG(3), #(REGSET_GP_OFF + 6 * REG_WIDTH)]
	ldp	REG(27), REG(28), [REG(3), #(REGSET_GP_OFF + 8 * REG_WIDTH)]

	ldp	q8,  q9,  [REG(3), #REGSET_FP_OFF]
	ldp	q10, q11, [REG(3), #(REGSET_FP_OFF + 2 * Q_WIDTH)]
	ldp	q12, q13, [REG(3), #(REGSET_FP_OFF + 4 * Q_WIDTH)]
	ldp	q14, q15, [REG(3), #(REGSET_FP_OFF + 6 * Q_WIDTH)]

	ldr	x10, [REG(3), #REGSET_FPCR_OFF]
	msr	fpcr, x10
	ldr	x10, [REG(3), #REGSET_FPSR_OFF]
	msr	fpsr, x10

	/* Nothing may use TLS until the real CTPIDR_EL0 is back. */
	ldr	REG(10), [REG(3), #REGSET_CTPIDR_OFF]
	msr	ctpidr_el0, REG(10)

	/* The switcher's outbuf, outlen, inbuf, and inlen. */
	mov	REG(3), REGN(sp)
	mov	x4, #SCRATCH_SIZE
	mov	REG(5), REGN(sp)
	mov	x6, #SCRATCH_SIZE
	blrs	REG(29), REG(0), REG(1)

	/*
	 * The switcher returns an errno in x0 with the carry flag set, like a
	 * syscall.  Return it negated, so that the caller can tell EAGAIN from
	 * a length.
	 */
	cneg	x0, x0, cs

	/* Store the registers to values before restoring the caller's. */
	ldr	REG(9), [REGN(sp), #SAVED_VALUES_OFF]
	stp	REG(19), REG(20), [REG(9), #REGSET_GP_OFF]
	stp	REG(21), REG(22), [REG(9), #(REGSET_GP_OFF + 2 * REG_WIDTH)]
	stp	REG(23), REG(24), [REG(9), #(REGSET_GP_OFF + 4 * REG_WIDTH)]
	stp	REG(25), REG(26), [REG(9), #(REGSET_GP_OFF + 6 * REG_WIDTH)]
	stp	REG(27), REG(28), [REG(9), #(REGSET_GP_OFF + 8 * REG_WIDTH)]

	stp	q8,  q9,  [REG(9), #REGSET_FP_OFF]
	stp	q10, q11, [REG(9), #(REGSET_FP_OFF + 2 * Q_WIDTH)]
	stp	q12, q13, [REG(9), #(REGSET_FP_OFF + 4 * Q_WIDTH)]
	stp	q14, q15, [REG(9), #(REGSET_FP_OFF + 6 * Q_WIDTH)]

	mrs	x10, fpcr
	str	x10, [REG(9), #REGSET_FPCR_OFF]
	mrs	x10, fpsr
	str	x10, [REG(9), #REGSET_FPSR_OFF]
	mrs	REG(10), ctpidr_el0
	str	REG(10), [REG(9), #REGSET_CTPIDR_OFF]

	ldr	REG(10), [REGN(sp), #DIRECT_CTPIDR_OFF]
	msr	ctpidr_el0, REG(10)
	ldr	x10, [REGN(sp), #DIRECT_FPCR_OFF]
	msr	fpcr, x10
	ldr	x10, [REGN(sp), #DIRECT_FPSR_OFF]
	msr	fpsr, x10
	ldr	REG(29), [REGN(sp), #DIRECT_C29_OFF]

	ldp	REG(19), REG(20), [REGN(sp), #DIRECT_GP_OFF]
	ldp	REG(21), REG(22), [REGN(sp), #(DIRECT_GP_OFF + 2 * REG_WIDTH)]
	ldp	REG(23), REG(24), [REGN(sp), #(DIRECT_GP_OFF + 4 * REG_WIDTH)]
	ldp	REG(25), REG(26), [REGN(sp), #(DIRECT_GP_OFF + 6 * REG_WIDTH)]
	ldp	REG(27), REG(28), [REGN(sp), #(DIRECT_GP_OFF + 8 * REG_WIDTH)]

	ldp	q8,  q9,  [REGN(sp), #DIRECT_FP_OFF]
	ldp	q10, q11, [REGN(sp), #(DIRECT_FP_OFF + 2 * Q_WIDTH)]
	ldp	q12, q13, [REGN(sp), #(DIRECT_FP_OFF + 4 * Q_WIDTH)]
	ldp	q14, q15, [REGN(sp), #(DIRECT_FP_OFF + 6 * Q_WIDTH)]

	ldr	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	add	REGN(sp), REGN(sp), #DIRECT_FRAME_SIZE

	RETURN
END(enter_switcher_with_markers)

GNU_PROPERTY_AARCH64_FEATURE_1_NOTE(GNU_PROPERTY_AARCH64_FEATURE_1_VAL)
