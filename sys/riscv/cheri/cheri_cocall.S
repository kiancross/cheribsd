/*-
 * Copyright (c) 2020 Edward Tomasz Napierala <trasz@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

#include "assym.inc"

#include <sys/errno.h>
#include <machine/asm.h>
#include <machine/cherireg.h>
#include <machine/switcher.h>

.option capmode

/*
 * Register usage: we save and restore csp and cra.  The rest gets zeroed;
 * the libc wrappers are responsible for saving and restoring the context.
 *
 * Layout of 'struct switchercb', pointed to by ct6/idc (caller) and,
 * later on, ct0 (callee), is described in sys/riscv/include/proc.h.
 */
#define	caller	ct6
#define	callee	ct0

#define	SWITCHER_ENTRY(sym)					\
	.text; .globl sym; .type sym,@object; .align 4; sym: .cfi_startproc

#define	SWITCHER_MARKER(x)					\
	.globl x; .type x,@object; x:

SWITCHER_ENTRY(switcher_cocall)
	/*
	 * Save the caller's stack pointer and return address (PCC)
	 * in the caller's control block.
	 *
	 * XXX: Make sure the IDC is cleared if we get a signal while here.
	 */
	csc	csp, SCB_CSP(caller)
	csc	cra, SCB_CRA(caller)

	/*
	 * Save the data transfer args.
	 */
	csc	ca3, SCB_OUTBUF(caller)
	csd	a4, SCB_OUTLEN(caller)
	csc	ca5, SCB_INBUF(caller)
	csd	a6, SCB_INLEN(caller)

	/*
	 * Unseal the callee's control block.
	 */
	clc	callee, SCB_TARGET_UNSEALCAP(caller)
	cunseal	callee, ca2, callee		/* Unseal the callee control block */

	/*
	 * Save the capability to the callee's control block in the caller
	 * context.
	 */
	csc	callee, SCB_TARGET_SCB(caller)
.Ltake_lock:
	/*
	 * Save the capability to the caller's control block in the callee
	 * context.  This also serves as the callee's spinlock.  The
	 * load-reserved and store-conditional pair stops two callers on
	 * different CPUs from both taking it.  The acquire pairs with
	 * coaccept's release of the spinlock (a fence, then a plain store),
	 * so we read the callee's context only after the callee has saved
	 * it.  The release also means that the callee's reply, which takes
	 * our SCB's address from the lock, sees the registers saved above,
	 * even if the reply runs on another CPU.
	 */
	clr.c.aq	ct1, SCB_CALLER_SCB(callee)
	cgettag	t2, ct1
	bnez	t2, .Llock_busy
	csc.c.rl	t3, caller, SCB_CALLER_SCB(callee)
	bnez	t3, .Ltake_lock

	/*
	 * If scb_borrower_td in the callee's scb is NULL, then
	 * the current thread is the caller thread and is going
	 * to borrow the callee thread.  Set scb_borrower_td in
	 * the caller's scb to the callee thread.  However, if
	 * scb_borrower_td is not NULL, then the callee's thread
	 * is returning to the callee and scb_borrower_thread
	 * needs to be set to NULL in the callee's scb.
	 *
	 * XXX: The non-NULL branch assumes that the callee's
	 * thread hosts this caller's code, and clears the
	 * record without checking.  Say A cocalls B, and
	 * B's reply leaves A's code on B's thread.  If C then
	 * cocalls B, this branch clears the record that A's
	 * code is on B's thread.  What A's next syscall then
	 * does depends on whether B has replied to C:
	 *
	 *  - Before the reply, the syscall runs as B.  See
	 *    cheribsdtest colocation_pending_incumbent_vacate.
	 *
	 *  - After the reply, B's record names C's thread, which is
	 *    not waiting in covacate(2), so the syscall retries for
	 *    ever in colocation_vacate().  See cheribsdtest
	 *    colocation_served_incumbent_vacate.
	 */
	clc	ct1, SCB_BORROWER_TD(callee)
	bnez	t1, 5f
	clc	ct4, SCB_HOME_TD(callee)
	csc	ct4, SCB_BORROWER_TD(caller)
	j	6f
5:
	csd	zero, SCB_BORROWER_TD(callee)
6:

	/*
	 * Put the caller cookie (caller's data capability with the tag
	 * stripped off) where the callee wants it.
	 */
	clc	ct5, SCB_COOKIEP(callee)
	beqz	t5, .Lcookie_done
	ccleartag	ca1, ca1
	csc	ca1, 0(ct5)
.Lcookie_done:

	/*
	 * Restore the callee's context.
	 */
	clc	csp, SCB_CSP(callee)
	clc	cra, SCB_CRA(callee)

	/*
	 * Do the data transfer.
	 *
	 * XXX: Could use some optimization.
	 */
	clc	ct4, SCB_INBUF(callee)
	cld	t5, SCB_INLEN(callee)

	/*
	 * Compare buffer sizes, put the smaller one into t5.
	 */
	mv	a0, t5
	bgeu	a4, t5, .Lcopy_loop
	mv	t5, a4
	mv	a0, a4

SWITCHER_MARKER(switcher_cocall_copy_start)
.Lcopy_loop:
	clc	ct2, 0(ca3)
	csc	ct2, 0(ct4)
	cincoffset ca3, ca3, CHERICAP_SIZE
	cincoffset ct4, ct4, CHERICAP_SIZE
	addi	t5, t5, -CHERICAP_SIZE
	bgtz	t5, .Lcopy_loop
SWITCHER_MARKER(switcher_cocall_copy_end)

	li	t0, 0

.Lreturn:
	/*
	 * XXX: We should use cclear here, but until it's supported in qemu, let's just...
	 */
	/* Preserve x1 (ra), and x2 (sp). */
	li x3, 0
	li x4, 0
	/* Preserve x5 (t0), used for errno (XXX). */
	li x6, 0
	li x7, 0
	li x8, 0
	li x9, 0
	/* Preserve x10 (a0), which is our return value. */
	li x11, 0
	li x12, 0
	li x13, 0
	li x14, 0
	li x15, 0
	li x16, 0
	li x17, 0
	li x18, 0
	li x19, 0
	li x20, 0
	li x21, 0
	li x22, 0
	li x23, 0
	li x24, 0
	li x25, 0
	li x26, 0
	li x27, 0
	li x28, 0
	li x29, 0
	li x30, 0
	li x31, 0

	/*
	 * "Return" to the callee, or to the caller if returning an error.
	 */
	cret
.Llock_busy:
	/*
	 * The spinlock is already taken.  Or is it?
	 */
	cgetlen	t2, ct1

	/*
	 * It is, go around.
	 */
	bnez	t2, .Ltake_lock
	nop

	/*
	 * No: length zero means we need to return error encoded as offset.
	 */
	cgetoffset	a0, ct1
	li	t0, 1
	j	.Lreturn

SWITCHER_MARKER(switcher_cocall_copy_onfault)
	/* Assumes a0 holds errno. */

	/* Clear state in the callee's scb. */
	clc	ct1, SCB_TARGET_SCB(caller)
	clc	ct2, SCB_COOKIEP(ct1)
	beqz	t2, .Lonfault_cookie_done
	csc	cnull, (ct2)
.Lonfault_cookie_done:
	fence	rw, w
	csc	cnull, SCB_CALLER_SCB(ct1)

	/* Clear state in the caller's scb. */
	csd	zero, SCB_BORROWER_TD(caller)
	csc	cnull, SCB_TARGET_SCB(caller)

	clc	csp, SCB_CSP(caller)
	clc	cra, SCB_CRA(caller)

	li	t0, 1
	j	.Lreturn

END(switcher_cocall)

eswitcher_cocall:
	.data
	.align	3
	.globl szswitcher_cocall
	.type szswitcher_cocall,@object
szswitcher_cocall:
	.long eswitcher_cocall - switcher_cocall
	.size szswitcher_cocall, . - szswitcher_cocall
