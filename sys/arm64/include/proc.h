/*-
 * Copyright (c) 1991 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *	from: FreeBSD: src/sys/i386/include/proc.h,v 1.11 2001/06/29
 */

#ifdef __arm__
#include <arm/proc.h>
#else /* !__arm__ */

#ifndef	_MACHINE_PROC_H_
#define	_MACHINE_PROC_H_

#include <machine/frame.h>

#ifdef CPU_CHERI
struct switchercb {
	/*
	 * SCB of the code that cocalled us.  This also serves as our
	 * spinlock.  Must be first, as the load-exclusive instructions
	 * don't take an offset.  It holds one of three things:
	 *
	 *  - NULL: no cocall is in progress, and a cocall can take the lock.
	 *
	 *  - A capability to the caller's SCB: a cocall is in progress.
	 *
	 *  - A zero-length capability whose offset is the errno that
	 *    cocall(2) returns: EAGAIN before the callee first calls
	 *    coaccept(2), EPROTOTYPE while it serves cocalls through
	 *    coaccept_slow(2), and ENOLINK once its thread has exited.
	 */
	struct switchercb * __capability	scb_caller_scb;

	/*
	 * SCB of the code we're cocalling into.
	 */
	struct switchercb * __capability	scb_target_scb;

	/*
	 * Home thread: the thread that called cosetup(2).
	 */
	struct thread * __capability		scb_home_td;

	/*
	 * SCB of the guest whose code runs on this SCB's home thread.  NULL
	 * or this SCB itself means that no guest runs there.
	 */
	struct switchercb * __capability	scb_guest_scb;

	/*
	 * SCB of the thread running this SCB's code now, or this SCB
	 * itself when the code is on its home thread.
	 */
	struct switchercb * __capability	scb_runner_scb;

	/*
	 * Copy of switcher_target_sealcap, with which the switcher unseals
	 * cocall targets.
	 */
	void * __capability			scb_target_unsealcap;

	/*
	 * Floating point.  The reason for this being here and not
	 * below is that the immediate offset range for ldr/str
	 * instructions is smaller when used with vector registers.
	 */
	__uint128_t				scb_q8;
	__uint128_t				scb_q9;
	__uint128_t				scb_q10;
	__uint128_t				scb_q11;
	__uint128_t				scb_q12;
	__uint128_t				scb_q13;
	__uint128_t				scb_q14;
	__uint128_t				scb_q15;

	/*
	 * Stack pointer and return address, saved on entry to the switcher.
	 */
	void * __capability			scb_csp;
	void * __capability			scb_cra;

	/*
	 * The outbuf, outlen, inbuf, and inlen arguments of cocall(2) or
	 * coaccept(2).
	 */
	const void * __capability		scb_outbuf;
	size_t					scb_outlen;
	void * __capability			scb_inbuf;
	size_t					scb_inlen;

	/*
	 * The cookiep argument of coaccept(2): where a cocall puts the
	 * caller's cookie, or NULL.
	 */
	void * __capability			scb_cookiep;

	/*
	 * Remaining callee-saved part of CPU context.
	 */
	void * __capability			scb_c19;
	void * __capability			scb_c20;
	void * __capability			scb_c21;
	void * __capability			scb_c22;
	void * __capability			scb_c23;
	void * __capability			scb_c24;
	void * __capability			scb_c25;
	void * __capability			scb_c26;
	void * __capability			scb_c27;
	void * __capability			scb_c28;

	/*
	 * CTPIDR_EL0.
	 */
	void * __capability			scb_tls;

	void * __capability			scb_fpcr;
	void * __capability			scb_fpsr;

};
#endif

struct ptrauth_key {
	uint64_t pa_key_lo;
	uint64_t pa_key_hi;
};

struct mdthread {
	int	md_spinlock_count;	/* (k) */
	register_t md_saved_daif;	/* (k) */
	uintptr_t md_canary;

	/*
	 * The pointer authentication keys. These are shared within a process,
	 * however this may change for some keys as the PAuth ABI Extension to
	 * ELF for the Arm 64-bit Architecture [1] is currently (July 2021) at
	 * an Alpha release quality so may change.
	 *
	 * [1] https://github.com/ARM-software/abi-aa/blob/main/pauthabielf64/pauthabielf64.rst
	 */
	struct {
		struct ptrauth_key apia;
		struct ptrauth_key apib;
		struct ptrauth_key apda;
		struct ptrauth_key apdb;
		struct ptrauth_key apga;
	} md_ptrauth_user;

	struct {
		struct ptrauth_key apia;
	} md_ptrauth_kern;

	uint64_t md_efirt_tmp;
	int md_efirt_dis_pf;

	int md_reserved0;
	uint64_t md_reserved[2];
};

struct mdproc {
#if __has_feature(capabilities)
	void * __capability md_sigcode;
#endif
	long	md_dummy;
};

#if __has_feature(capabilities)
#define	KINFO_PROC_SIZE		1248
#define	KINFO_PROC64_SIZE	1088
#else
#define	KINFO_PROC_SIZE	1088
#endif
#define	KINFO_PROC32_SIZE 816

#endif /* !_MACHINE_PROC_H_ */

#endif /* !__arm__ */
