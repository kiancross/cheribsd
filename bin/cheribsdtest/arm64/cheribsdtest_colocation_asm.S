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
 * Pure-assembly helpers for the colocation GP register-preservation tests.
 *
 * Each helper loads caller-supplied tagged-capability markers into
 * c19-c28, issues a single cocall (caller side) or coaccept (callee
 * side), then writes the post-call c19-c28 (full capabilities, tag +
 * bounds + perms + address) back through the caller-supplied vals[]
 * pointer.  Using tagged-capability markers means the test exercises
 * not just the 64-bit address half but the whole capability, so any
 * switcher bug that strips a tag, rewrites bounds, or clears
 * permissions would surface.
 *
 * The helpers are AAPCS-compliant -- they save the caller's c19-c28
 * on entry and restore them on exit.  The post-cocall / post-coaccept
 * register snapshot is captured to vals[] BEFORE the restore.  Order
 * matters here -- if the snapshot is taken after the restore, the
 * test silently masks itself.
 *
 * Only built for purecap; the asm assumes capability args in c0/c1,
 * a capability stack pointer, and a capability link register.
 *
 * x9 (REG(9)) is used as caller-saved scratch to hold the vals
 * pointer after the cocall/coaccept returns -- nothing else in the
 * helpers may rely on x9 surviving across that span.  Frame layout
 * is shared between the helpers; growing the saved-vals slot or
 * scratch buffer requires updating each.
 */

#include <machine/asm.h>
#include <sys/elf_common.h>

/*
 * Common stack frame layout used by both helpers:
 *
 *   [sp + 0 .. 15]                              : 16-byte scratch buffer
 *                                                  used as the cocall
 *                                                  send_buf / recv_buf.
 *   [sp + 16 .. 16 + REG_WIDTH - 1]             : saved link register.
 *   [sp + 16 + REG_WIDTH .. 16 + 2*REG_WIDTH-1] : saved caller-supplied
 *                                                  vals pointer.
 *   [sp + 16 + 2*REG_WIDTH .. ]                 : caller's saved
 *                                                  callee-saved register
 *                                                  contents.
 */

#define	SAVED_LR_OFF		16
#define	SAVED_VALS_OFF		(16 + REG_WIDTH)
#define	SAVED_REGS_OFF		(16 + 2 * REG_WIDTH)

#define	GP_SAVE_SIZE		160	/* 10 callee-saved c-regs * 16 */

#define	GP_FRAME_SIZE		(SAVED_REGS_OFF + GP_SAVE_SIZE)

/*
 * void gp_register_check_via_cocall(void *target,
 *     void * const *markers, void **vals);
 *
 * On entry: REG(0) = target, REG(1) = markers (10 caps), REG(2) = vals.
 * Loads markers[0..9] into c19..c28, issues a cocall, then writes the
 * post-cocall c19..c28 (full capabilities) into vals[0..9].  Caller's
 * c19..c28 are preserved across the call per AAPCS.
 */
ENTRY(gp_register_check_via_cocall)
	/* Allocate frame, save lr and vals. */
	sub	REGN(sp), REGN(sp), #GP_FRAME_SIZE
	str	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	str	REG(2), [REGN(sp), #SAVED_VALS_OFF]

	/* Save caller's c19-c28 (full caps) so we can restore them. */
	stp	REG(19), REG(20), [REGN(sp), #SAVED_REGS_OFF]
	stp	REG(21), REG(22), [REGN(sp), #(SAVED_REGS_OFF + 32)]
	stp	REG(23), REG(24), [REGN(sp), #(SAVED_REGS_OFF + 64)]
	stp	REG(25), REG(26), [REGN(sp), #(SAVED_REGS_OFF + 96)]
	stp	REG(27), REG(28), [REGN(sp), #(SAVED_REGS_OFF + 128)]

	/* Load markers[0..9] from REG(1) into c19-c28. */
	ldp	REG(19), REG(20), [REG(1)]
	ldp	REG(21), REG(22), [REG(1), #32]
	ldp	REG(23), REG(24), [REG(1), #64]
	ldp	REG(25), REG(26), [REG(1), #96]
	ldp	REG(27), REG(28), [REG(1), #128]

	/*
	 * Set up cocall(target, send_buf, send_size, recv_buf, recv_size).
	 * REG(0) (target) is already correct.  Use the in-frame scratch
	 * buffer for both send and recv.
	 */
	mov	REG(1), REGN(sp)
	mov	x2, #16
	mov	REG(3), REGN(sp)
	mov	x4, #16
	bl	cocall

	/*
	 * Recover vals into REG(9).  Snapshot post-cocall c19-c28
	 * through vals BEFORE restoring caller's c19-c28.
	 */
	ldr	REG(9), [REGN(sp), #SAVED_VALS_OFF]
	stp	REG(19), REG(20), [REG(9)]
	stp	REG(21), REG(22), [REG(9), #32]
	stp	REG(23), REG(24), [REG(9), #64]
	stp	REG(25), REG(26), [REG(9), #96]
	stp	REG(27), REG(28), [REG(9), #128]

	/* Restore caller's c19-c28. */
	ldp	REG(19), REG(20), [REGN(sp), #SAVED_REGS_OFF]
	ldp	REG(21), REG(22), [REGN(sp), #(SAVED_REGS_OFF + 32)]
	ldp	REG(23), REG(24), [REGN(sp), #(SAVED_REGS_OFF + 64)]
	ldp	REG(25), REG(26), [REGN(sp), #(SAVED_REGS_OFF + 96)]
	ldp	REG(27), REG(28), [REGN(sp), #(SAVED_REGS_OFF + 128)]

	/* Restore lr and tear down frame. */
	ldr	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	add	REGN(sp), REGN(sp), #GP_FRAME_SIZE

	RETURN
END(gp_register_check_via_cocall)

/*
 * void gp_register_check_via_coaccept(void *cookiep,
 *     void * const *markers, void **vals);
 *
 * Callee-side mirror of gp_register_check_via_cocall.  Loads
 * markers[0..9] into c19..c28, issues coaccept (which suspends the
 * worker until a cocall arrives), then on resumption writes the
 * post-coaccept c19..c28 into vals[0..9].
 *
 * REG(0) (cookiep) is passed through to coaccept; the C caller
 * supplies NULL.
 */
ENTRY(gp_register_check_via_coaccept)
	sub	REGN(sp), REGN(sp), #GP_FRAME_SIZE
	str	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	str	REG(2), [REGN(sp), #SAVED_VALS_OFF]

	/* Save caller's c19-c28 (full caps). */
	stp	REG(19), REG(20), [REGN(sp), #SAVED_REGS_OFF]
	stp	REG(21), REG(22), [REGN(sp), #(SAVED_REGS_OFF + 32)]
	stp	REG(23), REG(24), [REGN(sp), #(SAVED_REGS_OFF + 64)]
	stp	REG(25), REG(26), [REGN(sp), #(SAVED_REGS_OFF + 96)]
	stp	REG(27), REG(28), [REGN(sp), #(SAVED_REGS_OFF + 128)]

	/* Load markers[0..9] from REG(1) into c19-c28. */
	ldp	REG(19), REG(20), [REG(1)]
	ldp	REG(21), REG(22), [REG(1), #32]
	ldp	REG(23), REG(24), [REG(1), #64]
	ldp	REG(25), REG(26), [REG(1), #96]
	ldp	REG(27), REG(28), [REG(1), #128]

	/*
	 * coaccept(cookiep, send_buf, send_size, recv_buf, recv_size).
	 * REG(0) (cookiep) already correct.  Use the in-frame scratch
	 * buffer for both send and recv.
	 */
	mov	REG(1), REGN(sp)
	mov	x2, #16
	mov	REG(3), REGN(sp)
	mov	x4, #16
	bl	coaccept

	/*
	 * Recover vals into REG(9).  Snapshot post-coaccept c19-c28
	 * through vals BEFORE restoring caller's c19-c28.
	 */
	ldr	REG(9), [REGN(sp), #SAVED_VALS_OFF]
	stp	REG(19), REG(20), [REG(9)]
	stp	REG(21), REG(22), [REG(9), #32]
	stp	REG(23), REG(24), [REG(9), #64]
	stp	REG(25), REG(26), [REG(9), #96]
	stp	REG(27), REG(28), [REG(9), #128]

	/* Restore caller's c19-c28. */
	ldp	REG(19), REG(20), [REGN(sp), #SAVED_REGS_OFF]
	ldp	REG(21), REG(22), [REGN(sp), #(SAVED_REGS_OFF + 32)]
	ldp	REG(23), REG(24), [REGN(sp), #(SAVED_REGS_OFF + 64)]
	ldp	REG(25), REG(26), [REGN(sp), #(SAVED_REGS_OFF + 96)]
	ldp	REG(27), REG(28), [REGN(sp), #(SAVED_REGS_OFF + 128)]

	ldr	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	add	REGN(sp), REGN(sp), #GP_FRAME_SIZE

	RETURN
END(gp_register_check_via_coaccept)

GNU_PROPERTY_AARCH64_FEATURE_1_NOTE(GNU_PROPERTY_AARCH64_FEATURE_1_VAL)
