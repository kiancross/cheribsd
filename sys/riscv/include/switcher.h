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
 * genassym.c.  SCB_CALLER_SCB is a plain 0(X) because clr.c and csc.c
 * take no offset.
 */
#define	SCB_CALLER_SCB(X)	0(X)
#define	SCB_TARGET_SCB(X)	SCB_TARGET_SCB_OFF(X)
#define	SCB_HOME_TD(X)		SCB_HOME_TD_OFF(X)
#define	SCB_GUEST_SCB(X)	SCB_GUEST_SCB_OFF(X)
#define	SCB_RUNNER_SCB(X)	SCB_RUNNER_SCB_OFF(X)
#define	SCB_TARGET_UNSEALCAP(X)	SCB_TARGET_UNSEALCAP_OFF(X)
#define	SCB_CSP(X)		SCB_CSP_OFF(X)
#define	SCB_CRA(X)		SCB_CRA_OFF(X)
#define	SCB_OUTBUF(X)		SCB_OUTBUF_OFF(X)
#define	SCB_OUTLEN(X)		SCB_OUTLEN_OFF(X)
#define	SCB_INBUF(X)		SCB_INBUF_OFF(X)
#define	SCB_INLEN(X)		SCB_INLEN_OFF(X)
#define	SCB_COOKIEP(X)		SCB_COOKIEP_OFF(X)

#endif /* !_MACHINE_SWITCHER_H_ */
