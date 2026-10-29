/*-
 * Copyright (c) 2018 Edward Tomasz Napierala <trasz@FreeBSD.org>
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
 *
 * $FreeBSD$
 */

#ifndef _MACHINE_SWITCHER_H_
#define _MACHINE_SWITCHER_H_

/*
 * Operands that address the fields of struct switchercb through base
 * register X, for the switcher assembly.  The offsets come from
 * genassym.c.  SCB_CALLER_SCB is a plain [X] because ldaxr, stlxr, and
 * stlr take no offset.
 */
#define	SCB_CALLER_SCB(X)	[X]
#define	SCB_TARGET_SCB(X)	[X, #SCB_TARGET_SCB_OFF]
#define	SCB_HOME_TD(X)		[X, #SCB_HOME_TD_OFF]
#define	SCB_BORROWER_TD(X)	[X, #SCB_BORROWER_TD_OFF]
#define	SCB_TARGET_UNSEALCAP(X)	[X, #SCB_TARGET_UNSEALCAP_OFF]
#define	SCB_Q8(X)		[X, #SCB_Q8_OFF]
#define	SCB_Q9(X)		[X, #SCB_Q9_OFF]
#define	SCB_Q10(X)		[X, #SCB_Q10_OFF]
#define	SCB_Q11(X)		[X, #SCB_Q11_OFF]
#define	SCB_Q12(X)		[X, #SCB_Q12_OFF]
#define	SCB_Q13(X)		[X, #SCB_Q13_OFF]
#define	SCB_Q14(X)		[X, #SCB_Q14_OFF]
#define	SCB_Q15(X)		[X, #SCB_Q15_OFF]
#define	SCB_CSP(X)		[X, #SCB_CSP_OFF]
#define	SCB_CRA(X)		[X, #SCB_CRA_OFF]
#define	SCB_OUTBUF(X)		[X, #SCB_OUTBUF_OFF]
#define	SCB_OUTLEN(X)		[X, #SCB_OUTLEN_OFF]
#define	SCB_INBUF(X)		[X, #SCB_INBUF_OFF]
#define	SCB_INLEN(X)		[X, #SCB_INLEN_OFF]
#define	SCB_COOKIEP(X)		[X, #SCB_COOKIEP_OFF]
#define	SCB_C19(X)		[X, #SCB_C19_OFF]
#define	SCB_C20(X)		[X, #SCB_C20_OFF]
#define	SCB_C21(X)		[X, #SCB_C21_OFF]
#define	SCB_C22(X)		[X, #SCB_C22_OFF]
#define	SCB_C23(X)		[X, #SCB_C23_OFF]
#define	SCB_C24(X)		[X, #SCB_C24_OFF]
#define	SCB_C25(X)		[X, #SCB_C25_OFF]
#define	SCB_C26(X)		[X, #SCB_C26_OFF]
#define	SCB_C27(X)		[X, #SCB_C27_OFF]
#define	SCB_C28(X)		[X, #SCB_C28_OFF]
#define	SCB_TLS(X)		[X, #SCB_TLS_OFF]
#define	SCB_FPCR(X)		[X, #SCB_FPCR_OFF]
#define	SCB_FPSR(X)		[X, #SCB_FPSR_OFF]

#endif /* !_MACHINE_SWITCHER_H_ */
