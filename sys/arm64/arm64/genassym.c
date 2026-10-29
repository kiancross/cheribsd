/*-
 * Copyright (c) 2004 Olivier Houchard
 * Copyright (c) 2014 Andrew Turner
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
 */

#include <sys/param.h>
#include <sys/assym.h>
#include <sys/bus.h>
#include <sys/intr.h>
#include <sys/pcpu.h>
#include <sys/proc.h>

#include <machine/efi.h>
#include <machine/frame.h>
#include <machine/machdep.h>
#include <machine/pcb.h>

/* Sizeof arm64_bootparams, rounded to keep stack alignment */
ASSYM(BOOTPARAMS_SIZE, roundup2(sizeof(struct arm64_bootparams),
    STACKALIGNBYTES + 1));
ASSYM(BP_MODULEP, offsetof(struct arm64_bootparams, modulep));
ASSYM(BP_KERN_STACK, offsetof(struct arm64_bootparams, kern_stack));
ASSYM(BP_KERN_TTBR0, offsetof(struct arm64_bootparams, kern_ttbr0));
ASSYM(BP_BOOT_EL, offsetof(struct arm64_bootparams, boot_el));

ASSYM(EC_EFI_STATUS, offsetof(struct efirt_callinfo, ec_efi_status));
ASSYM(EC_FPTR, offsetof(struct efirt_callinfo, ec_fptr));
ASSYM(EC_ARG1, offsetof(struct efirt_callinfo, ec_arg1));
#ifdef __CHERI_PURE_CAPABILITY__
ASSYM(EC_ARGCNT, offsetof(struct efirt_callinfo, ec_argcnt));
ASSYM(EC_ARG2, offsetof(struct efirt_callinfo, ec_arg2));
ASSYM(EC_ARG3, offsetof(struct efirt_callinfo, ec_arg3));
ASSYM(EC_ARG4, offsetof(struct efirt_callinfo, ec_arg4));
ASSYM(EC_ARG5, offsetof(struct efirt_callinfo, ec_arg5));
#endif

ASSYM(PCPU_SIZE, sizeof(struct pcpu));
ASSYM(PC_CURPCB, offsetof(struct pcpu, pc_curpcb));
ASSYM(PC_CURTHREAD, offsetof(struct pcpu, pc_curthread));
ASSYM(PC_SSBD, offsetof(struct pcpu, pc_ssbd));

/* Size of pcb, rounded to keep stack alignment */
ASSYM(PCB_SIZE, roundup2(sizeof(struct pcb), STACKALIGNBYTES + 1));
ASSYM(PCB_SINGLE_STEP_SHIFT, PCB_SINGLE_STEP_SHIFT);
ASSYM(PCB_REGS, offsetof(struct pcb, pcb_x));
ASSYM(PCB_X19, PCB_X19);
ASSYM(PCB_SP, offsetof(struct pcb, pcb_sp));
#if __has_feature(capabilities)
ASSYM(PCB_TPIDR, offsetof(struct pcb, pcb_tpidr_el0));
ASSYM(PCB_CID, offsetof(struct pcb, pcb_cid_el0));
ASSYM(PCB_RDDC, offsetof(struct pcb, pcb_rddc_el0));
#else
ASSYM(PCB_TPIDRRO, offsetof(struct pcb, pcb_tpidrro_el0));
#endif
ASSYM(PCB_ONFAULT, offsetof(struct pcb, pcb_onfault));
ASSYM(PCB_FLAGS, offsetof(struct pcb, pcb_flags));

ASSYM(P_PID, offsetof(struct proc, p_pid));

#ifdef CPU_CHERI
/*
 * SCB_CALLER_SCB in <machine/switcher.h> has no offset, so
 * scb_caller_scb has no ASSYM line and must come first.
 */
_Static_assert(offsetof(struct switchercb, scb_caller_scb) == 0,
    "scb_caller_scb is not first in struct switchercb");
ASSYM(SCB_TARGET_SCB_OFF, offsetof(struct switchercb, scb_target_scb));
ASSYM(SCB_HOME_TD_OFF, offsetof(struct switchercb, scb_home_td));
ASSYM(SCB_BORROWER_TD_OFF, offsetof(struct switchercb, scb_borrower_td));
ASSYM(SCB_TARGET_UNSEALCAP_OFF,
    offsetof(struct switchercb, scb_target_unsealcap));
ASSYM(SCB_Q8_OFF, offsetof(struct switchercb, scb_q8));
ASSYM(SCB_Q9_OFF, offsetof(struct switchercb, scb_q9));
ASSYM(SCB_Q10_OFF, offsetof(struct switchercb, scb_q10));
ASSYM(SCB_Q11_OFF, offsetof(struct switchercb, scb_q11));
ASSYM(SCB_Q12_OFF, offsetof(struct switchercb, scb_q12));
ASSYM(SCB_Q13_OFF, offsetof(struct switchercb, scb_q13));
ASSYM(SCB_Q14_OFF, offsetof(struct switchercb, scb_q14));
ASSYM(SCB_Q15_OFF, offsetof(struct switchercb, scb_q15));
ASSYM(SCB_CSP_OFF, offsetof(struct switchercb, scb_csp));
ASSYM(SCB_CRA_OFF, offsetof(struct switchercb, scb_cra));
ASSYM(SCB_OUTBUF_OFF, offsetof(struct switchercb, scb_outbuf));
ASSYM(SCB_OUTLEN_OFF, offsetof(struct switchercb, scb_outlen));
ASSYM(SCB_INBUF_OFF, offsetof(struct switchercb, scb_inbuf));
ASSYM(SCB_INLEN_OFF, offsetof(struct switchercb, scb_inlen));
ASSYM(SCB_COOKIEP_OFF, offsetof(struct switchercb, scb_cookiep));
ASSYM(SCB_C19_OFF, offsetof(struct switchercb, scb_c19));
ASSYM(SCB_C20_OFF, offsetof(struct switchercb, scb_c20));
ASSYM(SCB_C21_OFF, offsetof(struct switchercb, scb_c21));
ASSYM(SCB_C22_OFF, offsetof(struct switchercb, scb_c22));
ASSYM(SCB_C23_OFF, offsetof(struct switchercb, scb_c23));
ASSYM(SCB_C24_OFF, offsetof(struct switchercb, scb_c24));
ASSYM(SCB_C25_OFF, offsetof(struct switchercb, scb_c25));
ASSYM(SCB_C26_OFF, offsetof(struct switchercb, scb_c26));
ASSYM(SCB_C27_OFF, offsetof(struct switchercb, scb_c27));
ASSYM(SCB_C28_OFF, offsetof(struct switchercb, scb_c28));
ASSYM(SCB_TLS_OFF, offsetof(struct switchercb, scb_tls));
ASSYM(SCB_FPCR_OFF, offsetof(struct switchercb, scb_fpcr));
ASSYM(SCB_FPSR_OFF, offsetof(struct switchercb, scb_fpsr));
#endif

ASSYM(SF_UC, offsetof(struct sigframe, sf_uc));
#ifdef COMPAT_FREEBSD64
ASSYM(SF_UC64, offsetof(struct sigframe64, sf_uc));
#endif

ASSYM(TD_PROC, offsetof(struct thread, td_proc));
ASSYM(TD_PCB, offsetof(struct thread, td_pcb));
ASSYM(TD_FLAGS, offsetof(struct thread, td_flags));
ASSYM(TD_AST, offsetof(struct thread, td_ast));
ASSYM(TD_FRAME, offsetof(struct thread, td_frame));
ASSYM(TD_LOCK, offsetof(struct thread, td_lock));
ASSYM(TD_MD_CANARY, offsetof(struct thread, td_md.md_canary));
ASSYM(TD_MD_EFIRT_TMP, offsetof(struct thread, td_md.md_efirt_tmp));

ASSYM(TF_SIZE, sizeof(struct trapframe));
ASSYM(TF_SP, offsetof(struct trapframe, tf_sp));
ASSYM(TF_LR, offsetof(struct trapframe, tf_lr));
ASSYM(TF_ELR, offsetof(struct trapframe, tf_elr));
#if __has_feature(capabilities)
ASSYM(TF_DDC, offsetof(struct trapframe, tf_ddc));
#endif
ASSYM(TF_SPSR, offsetof(struct trapframe, tf_spsr));
ASSYM(TF_ESR, offsetof(struct trapframe, tf_esr));
ASSYM(TF_X, offsetof(struct trapframe, tf_x));

ASSYM(INTR_ROOT_IRQ, INTR_ROOT_IRQ);
ASSYM(INTR_ROOT_FIQ, INTR_ROOT_FIQ);
