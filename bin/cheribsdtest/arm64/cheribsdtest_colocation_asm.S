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
 * Pure-assembly helpers for the colocation register-preservation tests.
 *
 * The GP helpers load caller-supplied tagged-capability markers into
 * c19-c28, issue a single cocall (caller side) or coaccept (callee
 * side), then write the post-call c19-c28 (full capabilities, tag +
 * bounds + perms + address) back through the caller-supplied vals[]
 * pointer.  Using tagged-capability markers means the test exercises
 * not just the 64-bit address half but the whole capability, so any
 * switcher bug that strips a tag, rewrites bounds, or clears
 * permissions would surface.
 *
 * The FP helpers do the same for d8-d15.
 *
 * The helpers are AAPCS-compliant -- they save the caller's
 * callee-saved registers (c19-c28 / d8-d15) on entry and restore them
 * on exit.  The post-cocall / post-coaccept register snapshot is
 * captured to vals[] BEFORE the restore.  Order matters here -- if
 * the snapshot is taken after the restore, the test silently masks
 * itself.
 *
 * Only built for purecap; the asm assumes capability args in c0/c1,
 * a capability stack pointer, and a capability link register.
 *
 * x9 (REG(9)) is used as caller-saved scratch to hold the vals
 * pointer after the cocall/coaccept returns -- nothing else in the
 * helpers may rely on x9 surviving across that span.  Frame layout
 * is shared between all helpers; growing the saved-vals slot or
 * scratch buffer requires updating each.
 *
 * The fp helpers rely on the cocall/coaccept path being FP-free --
 * any FP arithmetic between the marker load and the snapshot would
 * clobber d8-d15 and pollute the result.  cocall and coaccept are
 * integer-only, so the assumption holds.
 */

#include <machine/asm.h>
#include <sys/elf_common.h>
#include <sys/syscall.h>

#include "cheribsdtest_colocation_asm.h"

/*
 * Common stack frame layout used by all helpers:
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
#define	FP_SAVE_SIZE		128	/* 8 callee-saved q-regs * 16 */

#define	GP_FRAME_SIZE		(SAVED_REGS_OFF + GP_SAVE_SIZE)
#define	FP_FRAME_SIZE		(SAVED_REGS_OFF + FP_SAVE_SIZE)

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
 * void fp_register_check_via_cocall(void *target,
 *     const void *markers, void *vals);
 *
 * On entry: REG(0) = target, REG(1) = markers (8 q-regs = 128 bytes),
 * REG(2) = vals (8 q-regs = 128 bytes).  Loads markers into q8..q15,
 * issues a cocall, then writes the post-cocall q8..q15 (full 128-bit,
 * covering both d-low and the upper half of v) into vals.  Caller's
 * q8..q15 are preserved across the call per AAPCS.
 */
ENTRY(fp_register_check_via_cocall)
	sub	REGN(sp), REGN(sp), #FP_FRAME_SIZE
	str	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	str	REG(2), [REGN(sp), #SAVED_VALS_OFF]

	/* Save caller's q8-q15 (full 128 bits each). */
	stp	q8,  q9,  [REGN(sp), #SAVED_REGS_OFF]
	stp	q10, q11, [REGN(sp), #(SAVED_REGS_OFF + 32)]
	stp	q12, q13, [REGN(sp), #(SAVED_REGS_OFF + 64)]
	stp	q14, q15, [REGN(sp), #(SAVED_REGS_OFF + 96)]

	/* Load markers from REG(1) into q8-q15. */
	ldp	q8,  q9,  [REG(1)]
	ldp	q10, q11, [REG(1), #32]
	ldp	q12, q13, [REG(1), #64]
	ldp	q14, q15, [REG(1), #96]

	/* Set up and issue the cocall. */
	mov	REG(1), REGN(sp)
	mov	x2, #16
	mov	REG(3), REGN(sp)
	mov	x4, #16
	bl	cocall

	/*
	 * Snapshot post-cocall q8-q15 through vals BEFORE restoring
	 * caller's q8-q15.
	 */
	ldr	REG(9), [REGN(sp), #SAVED_VALS_OFF]
	stp	q8,  q9,  [REG(9)]
	stp	q10, q11, [REG(9), #32]
	stp	q12, q13, [REG(9), #64]
	stp	q14, q15, [REG(9), #96]

	/* Restore caller's q8-q15. */
	ldp	q8,  q9,  [REGN(sp), #SAVED_REGS_OFF]
	ldp	q10, q11, [REGN(sp), #(SAVED_REGS_OFF + 32)]
	ldp	q12, q13, [REGN(sp), #(SAVED_REGS_OFF + 64)]
	ldp	q14, q15, [REGN(sp), #(SAVED_REGS_OFF + 96)]

	/* Restore lr and tear down frame. */
	ldr	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	add	REGN(sp), REGN(sp), #FP_FRAME_SIZE

	RETURN
END(fp_register_check_via_cocall)

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

/*
 * void fp_register_check_via_coaccept(void *cookiep,
 *     const void *markers, void *vals);
 *
 * Callee-side mirror of fp_register_check_via_cocall.
 */
ENTRY(fp_register_check_via_coaccept)
	sub	REGN(sp), REGN(sp), #FP_FRAME_SIZE
	str	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	str	REG(2), [REGN(sp), #SAVED_VALS_OFF]

	/* Save caller's q8-q15 (full 128 bits each). */
	stp	q8,  q9,  [REGN(sp), #SAVED_REGS_OFF]
	stp	q10, q11, [REGN(sp), #(SAVED_REGS_OFF + 32)]
	stp	q12, q13, [REGN(sp), #(SAVED_REGS_OFF + 64)]
	stp	q14, q15, [REGN(sp), #(SAVED_REGS_OFF + 96)]

	/* Load markers from REG(1) into q8-q15. */
	ldp	q8,  q9,  [REG(1)]
	ldp	q10, q11, [REG(1), #32]
	ldp	q12, q13, [REG(1), #64]
	ldp	q14, q15, [REG(1), #96]

	/* Set up and issue the coaccept. */
	mov	REG(1), REGN(sp)
	mov	x2, #16
	mov	REG(3), REGN(sp)
	mov	x4, #16
	bl	coaccept

	/*
	 * Snapshot post-coaccept q8-q15 through vals BEFORE restoring
	 * caller's q8-q15.
	 */
	ldr	REG(9), [REGN(sp), #SAVED_VALS_OFF]
	stp	q8,  q9,  [REG(9)]
	stp	q10, q11, [REG(9), #32]
	stp	q12, q13, [REG(9), #64]
	stp	q14, q15, [REG(9), #96]

	/* Restore caller's q8-q15. */
	ldp	q8,  q9,  [REGN(sp), #SAVED_REGS_OFF]
	ldp	q10, q11, [REGN(sp), #(SAVED_REGS_OFF + 32)]
	ldp	q12, q13, [REGN(sp), #(SAVED_REGS_OFF + 64)]
	ldp	q14, q15, [REGN(sp), #(SAVED_REGS_OFF + 96)]

	ldr	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	add	REGN(sp), REGN(sp), #FP_FRAME_SIZE

	RETURN
END(fp_register_check_via_coaccept)

/*
 * void fp_register_check_across_unborrow(void *cookiep,
 *     const void *markers, void *vals);
 *
 * Callee-side, like fp_register_check_via_coaccept, but issues a syscall
 * (getpid) AFTER the coaccept resumes and BEFORE snapshotting q8-q15.
 * The coaccept leaves this worker borrowed on the caller's kernel
 * thread; the syscall triggers colocation_unborrow(), which migrates the
 * worker back onto its own thread by swapping the trapframe.  The
 * trapframe carries no FP/SIMD state, so this is the slow path on which
 * callee-saved q8-q15 can be lost -- even with a single client.  getpid
 * is integer-only and preserves q8-q15 by AAPCS, so any mismatch here is
 * the unborrow's doing, not the syscall's.  The syscall is issued raw
 * (no libc) so nothing AAPCS-compliant sits between the resume and the
 * snapshot.
 */
ENTRY(fp_register_check_across_unborrow)
	sub	REGN(sp), REGN(sp), #FP_FRAME_SIZE
	str	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	str	REG(2), [REGN(sp), #SAVED_VALS_OFF]

	/* Save caller's q8-q15 (full 128 bits each). */
	stp	q8,  q9,  [REGN(sp), #SAVED_REGS_OFF]
	stp	q10, q11, [REGN(sp), #(SAVED_REGS_OFF + 32)]
	stp	q12, q13, [REGN(sp), #(SAVED_REGS_OFF + 64)]
	stp	q14, q15, [REGN(sp), #(SAVED_REGS_OFF + 96)]

	/* Load markers from REG(1) into q8-q15. */
	ldp	q8,  q9,  [REG(1)]
	ldp	q10, q11, [REG(1), #32]
	ldp	q12, q13, [REG(1), #64]
	ldp	q14, q15, [REG(1), #96]

	/* Set up and issue the coaccept. */
	mov	REG(1), REGN(sp)
	mov	x2, #16
	mov	REG(3), REGN(sp)
	mov	x4, #16
	bl	coaccept

	/*
	 * Now borrowed on the caller's thread: force the unborrow with a
	 * raw getpid before snapshotting, so q8-q15 are sampled after the
	 * kernel has migrated this worker back to its own thread.
	 */
	mov	x8, #SYS_getpid
	svc	#0

	/*
	 * Snapshot post-unborrow q8-q15 through vals BEFORE restoring
	 * caller's q8-q15.
	 */
	ldr	REG(9), [REGN(sp), #SAVED_VALS_OFF]
	stp	q8,  q9,  [REG(9)]
	stp	q10, q11, [REG(9), #32]
	stp	q12, q13, [REG(9), #64]
	stp	q14, q15, [REG(9), #96]

	/* Restore caller's q8-q15. */
	ldp	q8,  q9,  [REGN(sp), #SAVED_REGS_OFF]
	ldp	q10, q11, [REGN(sp), #(SAVED_REGS_OFF + 32)]
	ldp	q12, q13, [REGN(sp), #(SAVED_REGS_OFF + 64)]
	ldp	q14, q15, [REGN(sp), #(SAVED_REGS_OFF + 96)]

	ldr	REGN(lr), [REGN(sp), #SAVED_LR_OFF]
	add	REGN(sp), REGN(sp), #FP_FRAME_SIZE

	RETURN
END(fp_register_check_across_unborrow)

/*
 * Direct switcher entry helper.
 *
 * The helpers above all go through libsys' cocall/coaccept C
 * wrappers, which means the wrapper's AAPCS prologue/epilogue saves
 * and restores the very registers we are trying to test -- a
 * switcher bug that mishandles c19-c28 / q8-q15 is silently papered
 * over by the wrapper, and the via_cocall / via_coaccept tests
 * still pass.
 *
 * The helper below skips the C wrapper and branches into the
 * switcher entry directly via blrs, the same way the _cocall.S /
 * _coaccept.S trampolines do.  Whether it enters switcher_cocall or
 * switcher_coaccept is decided entirely by which sealed code+data
 * pair the C caller obtained from _cosetup() and passed in, so one
 * helper serves both directions.  The only AAPCS-compliant code on
 * the path between marker load and post-switcher snapshot is the
 * helper itself, and it deliberately performs the load AFTER its own
 * callee-saved save and the snapshot BEFORE its restore, so anything
 * the switcher loses on the round trip is visible to the test.
 *
 * Markers cover the full set tracked by the switcher in one shot:
 * c19-c28, q8-q15, FPCR, FPSR, and CTPIDR_EL0.  The helper must
 * save, stage and restore the full set regardless of which class is
 * under test, so covering them all in one invocation is free.
 *
 * Mutating CTPIDR_EL0 to a non-TLS marker would fault any C code
 * that touches errno, _trace_cocall, stack canaries, or compiler-
 * emitted TLS lookups, so the marker load and the snapshot live
 * inside the asm helper without any C between them, and the helper
 * restores the real CTPIDR_EL0 (saved on entry) before returning to
 * its C caller.  FPCR / FPSR are restored on the same principle to
 * avoid contaminating the caller's FP state.
 */

/*
 * DSWI (direct-switcher) helper frame layout (offsets from csp):
 *
 *   [DSWI_SCRATCH_OFF .. +16) : 16-byte outbuf/inbuf scratch
 *   [DSWI_CTPIDR_OFF  .. +16) : saved real CTPIDR_EL0 (capability)
 *   [DSWI_FPCR_OFF    .. +8)  : saved real FPCR
 *   [DSWI_FPSR_OFF    .. +8)  : saved real FPSR
 *   [DSWI_LR_OFF      .. +16) : saved clr
 *   [DSWI_VALS_OFF    .. +16) : saved vals pointer
 *   [DSWI_FP29_OFF    .. +16) : saved c29 (frame pointer; the
 *                                switcher tail clears x29 on the way
 *                                back so we have to reinstate it)
 *   [DSWI_GP_OFF   .. +160)   : saved caller's c19-c28
 *   [DSWI_FP_OFF   .. +128)   : saved caller's q8-q15
 *
 * Frame size 384 keeps csp 16-byte aligned.  The DSWI_* frame
 * offsets are local to this helper; the struct switcher_regset
 * offsets it reads and writes are the SR_* constants from
 * cheribsdtest_colocation_asm.h.
 */
#define	DSWI_SCRATCH_OFF	0
#define	DSWI_CTPIDR_OFF		16
#define	DSWI_FPCR_OFF		32
#define	DSWI_FPSR_OFF		40
#define	DSWI_LR_OFF		48
#define	DSWI_VALS_OFF		64
#define	DSWI_FP29_OFF		80
#define	DSWI_GP_OFF		96
#define	DSWI_FP_OFF		256
#define	DSWI_FRAME_SIZE		384

/*
 * ssize_t switcher_entry_check_direct(void *code, void *data,
 *     void *target_or_cookiep,
 *     const struct switcher_regset *markers,
 *     struct switcher_regset *vals);
 *
 * On entry: c0/c1 = the sealed code+data pair from _cosetup(), c3 =
 * markers, c4 = vals.  c2 is forwarded to the switcher untouched:
 * with a COSETUP_COCALL pair it is the sealed callee SCB to call;
 * with a COSETUP_COACCEPT pair it is the cookie pointer (the C
 * caller passes NULL, and the first coaccept on a thread parks via
 * copark(2) until a cocall arrives).  Returns the received length,
 * or a negated errno on failure.
 */
ENTRY(switcher_entry_check_direct)
	sub	csp, csp, #DSWI_FRAME_SIZE

	str	clr, [csp, #DSWI_LR_OFF]
	str	c29, [csp, #DSWI_FP29_OFF]
	str	c4,  [csp, #DSWI_VALS_OFF]

	/*
	 * Snapshot the real CTPIDR_EL0 / FPCR / FPSR so we can put
	 * them back before any C code resumes.
	 */
	mrs	c10, ctpidr_el0
	str	c10, [csp, #DSWI_CTPIDR_OFF]
	mrs	x10, fpcr
	str	x10, [csp, #DSWI_FPCR_OFF]
	mrs	x10, fpsr
	str	x10, [csp, #DSWI_FPSR_OFF]

	stp	c19, c20, [csp, #DSWI_GP_OFF]
	stp	c21, c22, [csp, #(DSWI_GP_OFF + 32)]
	stp	c23, c24, [csp, #(DSWI_GP_OFF + 64)]
	stp	c25, c26, [csp, #(DSWI_GP_OFF + 96)]
	stp	c27, c28, [csp, #(DSWI_GP_OFF + 128)]

	stp	q8,  q9,  [csp, #DSWI_FP_OFF]
	stp	q10, q11, [csp, #(DSWI_FP_OFF + 32)]
	stp	q12, q13, [csp, #(DSWI_FP_OFF + 64)]
	stp	q14, q15, [csp, #(DSWI_FP_OFF + 96)]

	/*
	 * Load markers from c3 into c19-c28, q8-q15, FPCR, FPSR and
	 * CTPIDR_EL0.  CTPIDR_EL0 goes last; from this point until
	 * the post-snapshot restore below, no instruction may touch
	 * TLS-backed state.
	 */
	ldp	c19, c20, [c3, #(SR_GP_OFF + 0)]
	ldp	c21, c22, [c3, #(SR_GP_OFF + 32)]
	ldp	c23, c24, [c3, #(SR_GP_OFF + 64)]
	ldp	c25, c26, [c3, #(SR_GP_OFF + 96)]
	ldp	c27, c28, [c3, #(SR_GP_OFF + 128)]

	ldp	q8,  q9,  [c3, #(SR_FP_OFF + 0)]
	ldp	q10, q11, [c3, #(SR_FP_OFF + 32)]
	ldp	q12, q13, [c3, #(SR_FP_OFF + 64)]
	ldp	q14, q15, [c3, #(SR_FP_OFF + 96)]

	ldr	x10, [c3, #SR_FPCR_OFF]
	msr	fpcr, x10
	ldr	x10, [c3, #SR_FPSR_OFF]
	msr	fpsr, x10

	ldr	c10, [c3, #SR_CTPIDR_OFF]
	msr	ctpidr_el0, c10

	/*
	 * c0, c1 and c2 are already in place.  Set up the
	 * data-transfer args using the in-frame scratch buffer for
	 * both outbuf and inbuf.
	 */
	mov	c3, csp
	mov	x4, #16
	mov	c5, csp
	mov	x6, #16

	/*
	 * Branch into the switcher.  blrs unseals the c0/c1 sealed
	 * pair, sets PC to the unsealed code, c29 to the unsealed
	 * data (this thread's SCB) and clr to the next-PC -- exactly
	 * what libsys' _cocall / _coaccept do.
	 */
	blrs	c29, c0, c1

	/*
	 * The switcher reports failure the way a syscall does: carry
	 * flag set and the errno value in x0 (the libsys trampolines
	 * handle it with "b.cs cerror", like any syscall stub).  Fold
	 * that into the return value -- negated errno on failure,
	 * received length on success -- while the flags are still
	 * fresh; nothing below touches x0 again.
	 */
	cneg	x0, x0, cs

	/*
	 * On return c19-c28, q8-q15, FPCR, FPSR and CTPIDR_EL0 should
	 * each hold the marker we set, restored by the switcher from
	 * the SCB it saved them into on the way in.  Snapshot them
	 * BEFORE restoring the real values; the order matters -- a
	 * snapshot taken after the restore would silently mask any
	 * switcher bug.
	 */
	ldr	c10, [csp, #DSWI_VALS_OFF]

	stp	c19, c20, [c10, #(SR_GP_OFF + 0)]
	stp	c21, c22, [c10, #(SR_GP_OFF + 32)]
	stp	c23, c24, [c10, #(SR_GP_OFF + 64)]
	stp	c25, c26, [c10, #(SR_GP_OFF + 96)]
	stp	c27, c28, [c10, #(SR_GP_OFF + 128)]

	stp	q8,  q9,  [c10, #(SR_FP_OFF + 0)]
	stp	q10, q11, [c10, #(SR_FP_OFF + 32)]
	stp	q12, q13, [c10, #(SR_FP_OFF + 64)]
	stp	q14, q15, [c10, #(SR_FP_OFF + 96)]

	mrs	x11, fpcr
	str	x11, [c10, #SR_FPCR_OFF]
	mrs	x11, fpsr
	str	x11, [c10, #SR_FPSR_OFF]

	mrs	c11, ctpidr_el0
	str	c11, [c10, #SR_CTPIDR_OFF]

	/* Reinstate real CTPIDR_EL0 / FPCR / FPSR before any C runs. */
	ldr	c11, [csp, #DSWI_CTPIDR_OFF]
	msr	ctpidr_el0, c11
	ldr	x11, [csp, #DSWI_FPCR_OFF]
	msr	fpcr, x11
	ldr	x11, [csp, #DSWI_FPSR_OFF]
	msr	fpsr, x11

	ldp	c19, c20, [csp, #DSWI_GP_OFF]
	ldp	c21, c22, [csp, #(DSWI_GP_OFF + 32)]
	ldp	c23, c24, [csp, #(DSWI_GP_OFF + 64)]
	ldp	c25, c26, [csp, #(DSWI_GP_OFF + 96)]
	ldp	c27, c28, [csp, #(DSWI_GP_OFF + 128)]

	ldp	q8,  q9,  [csp, #DSWI_FP_OFF]
	ldp	q10, q11, [csp, #(DSWI_FP_OFF + 32)]
	ldp	q12, q13, [csp, #(DSWI_FP_OFF + 64)]
	ldp	q14, q15, [csp, #(DSWI_FP_OFF + 96)]

	ldr	clr, [csp, #DSWI_LR_OFF]
	ldr	c29, [csp, #DSWI_FP29_OFF]

	add	csp, csp, #DSWI_FRAME_SIZE

	RETURN
END(switcher_entry_check_direct)

GNU_PROPERTY_AARCH64_FEATURE_1_NOTE(GNU_PROPERTY_AARCH64_FEATURE_1_VAL)
