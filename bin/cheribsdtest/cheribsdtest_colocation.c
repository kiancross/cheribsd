/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 SRI International
 * Copyright (c) 2026 Kian Cross
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under Defense Advanced Research Projects Agency (DARPA)
 * Contract No. HR001122C0110 ("ETC").
 *
 * Portions of this software were developed by Kian Cross at the
 * University of Cambridge Computer Laboratory (Department of Computer
 * Science and Technology) under Defense Advanced Research Projects
 * Agency / Air Force Research Laboratory (DARPA/AFRL) Contract
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

#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <kvm.h>
#include <libprocstat.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>

#include "cheribsdtest.h"

static bool
is_colocated_with_parent(void)
{
	struct procstat *psp;
	struct kinfo_proc *kipp;
	struct kinfo_vmentry *kivp;
	pid_t pid, ppid;
	uint pcnt, vmcnt;
	bool found_self, found_parent;

	pid = getpid();
	ppid = getppid();

	psp = procstat_open_sysctl();
	if (psp == NULL)
		err(EX_OSERR, "procstat_open_sysctl");

	kipp = procstat_getprocs(psp, KERN_PROC_PID, getpid(), &pcnt);
	if (kipp == NULL)
		err(EX_OSERR, "procstat_getprocs");
	if (pcnt != 1)
		warnx("got %d processes", pcnt);

	kivp = procstat_getvmmap(psp, kipp, &vmcnt);
	if (kivp == NULL)
		err(EX_OSERR, "procstat_getvmmap");

	found_self = found_parent = false;
	for (u_int i = 0; i < vmcnt; i++) {
		if (kivp[i].kve_pid == pid)
			found_self = true;
		if (kivp[i].kve_pid == ppid)
			found_parent = true;
	}
	if (!found_self)
		errx(EX_SOFTWARE, "Didn't find self in vmstate");

	procstat_freevmmap(psp, kivp);
	procstat_freeprocs(psp, kipp);
	procstat_close(psp);
	return (found_parent);
}

#ifdef CHERIBSD_DYNAMIC_TESTS
static void
coexec_child_cf(void)
{
	if (is_colocated_with_parent())
		exit (0);
	errx(EX_OSERR, "Not colocated with parent");
}

CHERIBSDTEST(colocation_coexec_child,
    "Check that we can coexecve a child and we share a vmspace",
    .ct_child_func = coexec_child_cf)
{
	int pfd, pid;

	pid = pdfork(&pfd, 0);
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		int res;

		waitpid(pid, &res, 0);
		if (res == 0) {
			cheribsdtest_success();
		} else if (WIFEXITED(res)) {
			cheribsdtest_failure_errx(
			    "coexecved process exited with %d",
			    WEXITSTATUS(res));
		} else {
			cheribsdtest_failure_errx(
			    "coexecved process failed with status 0x%x", res);
		}
	}
}

/*
 * colocation_coaccept_slow - test runner, forks and
 * coexecs a child, and then spins waiting for the child to register
 * a service. Once it has done so, it cocall's into the service.
 * The child registers a service and calls coaccept, does some
 * validation, and then calls coaccept again to return to the caller.
 * Both send their own pid and validate what they recieve.
 */
static void
coaccept_slow_cf(void)
{
	pid_t caller_pid, parent_pid;
	/*
	 * We use intcapt_t instead of pid_t because the cocall API requires
	 * that their sizes and addresses are 16-byte aligned.
	 */
	intcap_t my_pid;
	intcap_t recvd_pid;
	int error;

	if (!is_colocated_with_parent())
		errx(EX_OSERR, "Not colocated with parent");

	my_pid = getpid();
	parent_pid = getppid();

	error = cosetup(COSETUP_COACCEPT);
	if (error != 0)
		err(EX_OSERR, "cosetup");

	error = coregister(/* ctp->ct_name */ "XXX", NULL);
	if (error != 0)
		err(EX_OSERR, "coregister");

	error = coaccept_slow(NULL, &my_pid, sizeof(my_pid), &recvd_pid, sizeof(recvd_pid));
	if (error < 0)
		err(EX_OSERR, "coaccept");

	if (parent_pid != recvd_pid)
		errx(EX_SOFTWARE, "parent_pid %d != recvd_pid %d", parent_pid,
		    (pid_t) recvd_pid);

	error = cogetpid(&caller_pid);
	if (error != 0)
		cheribsdtest_failure_err("cogetpid");
	if (parent_pid != caller_pid)
		errx(EX_SOFTWARE, "parent_pid %d != caller_pid %d", parent_pid,
		    caller_pid);

	/*
	 * Return from cocall.  Should never return as there won't be
	 * another cocall.
	 */
	error = coaccept_slow(NULL, &my_pid, sizeof(my_pid), &recvd_pid, sizeof(recvd_pid));
	if (error < 0)
		err(EX_OSERR, "coaccept");
	err(EX_SOFTWARE, "Second coaccept returned.");
}

CHERIBSDTEST(colocation_coaccept_slow,
    "Configure the child to coaccept and handle one cocall",
    .ct_child_func = coaccept_slow_cf)
{
	pid_t fork_pid;
	/*
	 * We use intcapt_t instead of pid_t because the cocall API requires
	 * that their sizes and addresses are 16-byte aligned.
	 */
	intcap_t my_pid;
	intcap_t recvd_pid;
	int pfd;

	if (is_colocated_with_parent())
		cheribsdtest_failure_errx(
		    "test runner colocated with main " PROG "process");

	my_pid = getpid();

	fork_pid = pdfork(&pfd, 0);
	if (fork_pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (fork_pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		void *target;
		int error;
		int res;

		error = cosetup(COSETUP_COCALL);
		if (error != 0)
			err(EX_OSERR, "cosetup");

		/*
		 * We need to wait for the child to coregister. Right
		 * now the best we can do is spin unless we use a pipe/socket
		 * to synchronize.
		 *
		 * XXX: set a timeout?
		 */
		while ((error = colookup(/* ctp->ct_name */ "XXX", &target)) != 0 &&
		    errno == ESRCH && waitpid(fork_pid, &res, WNOHANG) == 0)
			;
		if (error != 0)
			cheribsdtest_failure_err("colookup");

		/*
		 * There's potential race between a successful colookup
		 * following the child's coregister and the child entering
		 * coaccept so we loop if we lose the race.
		 *
		 * XXX: set a timeout?
		 */
		while ((error = cocall_slow(target, &my_pid, sizeof(my_pid),
		    &recvd_pid, sizeof(recvd_pid))) < 0 && errno == EAGAIN)
			;
		if (error < 0)
			cheribsdtest_failure_err("cocall");

		if (recvd_pid != fork_pid) {
			cheribsdtest_failure_errx("recvd_pid %d != fork_pid %d",
			    (pid_t) recvd_pid, fork_pid);
		}

		/*
		 * The child process is now back in coaccept so signal
		 * the process to exit and wait for it.
		 */
		pdkill(pfd, SIGHUP);
		waitpid(fork_pid, &res, 0);
		if (WIFSIGNALED(res) && WTERMSIG(res) == SIGHUP) {
			cheribsdtest_success();
		} else if (WIFEXITED(res)) {
			cheribsdtest_failure_errx(
			    "coexecved process exited with %d",
			    WEXITSTATUS(res));
		} else {
			cheribsdtest_failure_errx(
			    "coexecved process failed with status 0x%x", res);
		}
	}
}

/* Excluded under c18n: a separate cocall fast-path issue causes SIGILL. */
#ifndef CHERIBSD_C18N_TESTS

static void
burn_cpu(unsigned long iters)
{
	unsigned long x = 1;

	for (unsigned long i = 0; i < iters; i++) {
		x = x * 1664525 + 1013904223;

		/* Prevent the compiler from eliding the loop. */
		asm volatile("" : "+r"(x));
	}
}

static double
user_cpu_time_for_pid(pid_t pid)
{
	struct procstat *ps;
	struct kinfo_proc *kp;
	struct rusage *ru;
	unsigned int cnt;
	double cpu;

	ps = procstat_open_sysctl();
	if (ps == NULL)
		return (-1);

	kp = procstat_getprocs(ps, KERN_PROC_PID, pid, &cnt);
	if (kp == NULL || cnt == 0) {
		procstat_close(ps);
		return (-1);
	}

	ru = &kp[0].ki_rusage;
	cpu = ru->ru_utime.tv_sec + ru->ru_utime.tv_usec * 1e-6;

	procstat_freeprocs(ps, kp);
	procstat_close(ps);

	return (cpu);
}

#define	COLOCATION_ACCOUNTING_SERVICE	"colocation_accounting"

static void
colocation_accounting_worker(void)
{
	intcap_t buf = 0;
	ssize_t received;

	if (cosetup(COSETUP_COACCEPT) != 0)
		err(EX_OSERR, "cosetup");

	if (coregister(COLOCATION_ACCOUNTING_SERVICE, NULL) != 0)
		err(EX_OSERR, "coregister");

	received = coaccept(NULL, &buf, sizeof(buf), &buf, sizeof(buf));
	if (received < 0)
		err(EX_OSERR, "coaccept");

	/*
	 * Tuned on Morello: long enough to register on the scheduler
	 * tick, short enough to keep the test fast.
	 */
	burn_cpu(20000000);

	received = coaccept(NULL, &buf, sizeof(buf), &buf, sizeof(buf));
	if (received < 0)
		err(EX_OSERR, "coaccept");

	err(EX_SOFTWARE, "Second coaccept returned.");
}

CHERIBSDTEST(colocation_accounting,
    "Check that work done in a cocall is accounted to the correct coprocess",
    .ct_flags = CT_FLAG_SLOW,
    .ct_child_func = colocation_accounting_worker,
    .ct_xfail_reason =
	"Borrowing callee CPU time is not yet attributed to the callee process by the kernel")
{
	void *target;
	double caller_start, callee_start, caller_end, callee_end;
	double caller_delta, callee_delta;
	intcap_t buf = 0;
	pid_t pid, self_pid;
	int error;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		self_pid = getpid();

		error = cosetup(COSETUP_COCALL);
		if (error != 0)
			cheribsdtest_failure_err("cosetup");

		/*
		 * We need to wait for the child to coregister.  Right
		 * now the best we can do is spin unless we use a pipe/socket
		 * to synchronize.
		 *
		 * XXX: set a timeout?
		 */
		while ((error = colookup(COLOCATION_ACCOUNTING_SERVICE,
		    &target)) != 0 &&
		    errno == ESRCH && waitpid(pid, NULL, WNOHANG) == 0)
			;
		if (error != 0)
			cheribsdtest_failure_err("colookup");

		caller_start = user_cpu_time_for_pid(self_pid);
		callee_start = user_cpu_time_for_pid(pid);

		if (cocall(target, &buf, sizeof(buf), &buf, sizeof(buf)) < 0)
			cheribsdtest_failure_err("cocall");

		caller_end = user_cpu_time_for_pid(self_pid);
		callee_end = user_cpu_time_for_pid(pid);

		caller_delta = caller_end - caller_start;
		callee_delta = callee_end - callee_start;

		/*
		 * Pass if the callee accumulated clearly more user CPU
		 * time than the caller during the cocall.  The 1ms floor
		 * guards against false positives when both samples land
		 * below procstat's tick resolution; the 100x ratio
		 * confirms the kernel attributed the burn_cpu work to
		 * the callee process even though the callee ran on the
		 * caller's borrowed kernel thread.
		 */
		if (callee_delta > 0.001 && callee_delta > caller_delta * 100) {
			cheribsdtest_success();
		} else {
			cheribsdtest_failure_errx(
			    "CPU time not correctly accounted: "
			    "caller=%.6fs callee=%.6fs",
			    caller_delta, callee_delta);
		}
	}
}

#endif /* !CHERIBSD_C18N_TESTS */
#endif

static void
exec_child_cf(void)
{
	if (!is_colocated_with_parent())
		exit (0);
	/*
	 * No output because we might be coexeced if opportunistic
	 * coexecve is enabled.
	 */
	exit(1);
}

CHERIBSDTEST(colocation_exec_child,
    "Check that we do not share a namespace with execve'd child",
    .ct_child_func = exec_child_cf)
{
	int pfd, pid;

	pid = pdfork(&pfd, 0);
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_exec_child();
	} else {
		int res;

		waitpid(pid, &res, 0);
		if (res == 0) {
			cheribsdtest_success();
		} else if (WIFEXITED(res) && WEXITSTATUS(res) == 1) {
			/*
			 * XXX: this might happen if sysctl
			 * kern.opportunistic_coexecve=1, but that isn't
			 * the default and this doesn't currently happen
			 * if it is enabled.
			 */
			cheribsdtest_failure_errx(
			    "execved process is co-located with parent");
		} else {
			cheribsdtest_failure_errx(
			    "execved process failed with status 0x%x", res);
		}
	}
}
