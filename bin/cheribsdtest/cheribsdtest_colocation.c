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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "cheribsdtest.h"
#include "cheribsdtest_colocation_asm.h"

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

static void *
wait_for_service(const char *service, pid_t worker)
{
	void *target;
	int error;

	if (cosetup(COSETUP_COCALL) != 0)
		cheribsdtest_failure_err("cosetup");

	/*
	 * Spin until the worker has registered the service.  The
	 * waitpid call escapes the loop if the worker dies first;
	 * worker liveness is the only cheap signal we have without
	 * a pipe/socket synchronisation channel.
	 *
	 * XXX: set a timeout?
	 */
	while ((error = colookup(service, &target)) != 0 &&
	    errno == ESRCH && waitpid(worker, NULL, WNOHANG) == 0)
		;

	if (error != 0)
		cheribsdtest_failure_err("colookup");

	return (target);
}

static void
cocall_or_fail(void *target, void *send_buf, size_t send_size,
    void *recv_buf, size_t recv_size)
{
	if (cocall(target, send_buf, send_size, recv_buf, recv_size) < 0)
		cheribsdtest_failure_err("cocall");
}

/* Excluded under c18n: a separate cocall fast-path issue causes SIGILL. */
#ifndef CHERIBSD_C18N_TESTS

#define	COLOCATION_SINGLE_CLIENT_SERVICE	"colocation_single_client"

static void
colocation_single_client_worker(void)
{
	intcap_t buf = 0;

	if (cosetup(COSETUP_COACCEPT) != 0)
		err(EX_OSERR, "cosetup");

	if (coregister(COLOCATION_SINGLE_CLIENT_SERVICE, NULL) != 0)
		err(EX_OSERR, "coregister");

	if (coaccept(NULL, &buf, sizeof(buf), &buf, sizeof(buf)) < 0)
		err(EX_OSERR, "coaccept");

	/*
	 * This syscall unborrows B onto its home thread TB so the next coaccept
	 * hands the caller's context onto TB.
	 */
	(void)getpid();

	if (coaccept(NULL, &buf, sizeof(buf), &buf, sizeof(buf)) < 0)
		err(EX_OSERR, "coaccept");

	err(EX_SOFTWARE, "second coaccept returned");
}

/*
 * Confirms the borrow/unborrow round trip is correct with a single
 * uncontended borrower.
 *
 *	A>B
 *	B@
 *	A<B	=> {TB->A}
 *	A@	|= {TA->A}
 */
CHERIBSDTEST(colocation_single_client_unborrow,
    "A single caller's syscall after a cocall round trip must unborrow back "
    "to its own thread and see its own pid",
    .ct_child_func = colocation_single_client_worker)
{
	void *target;
	intcap_t buf = 0;
	pid_t pid, my_pid, observed;

	my_pid = getpid();

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("fork");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_SINGLE_CLIENT_SERVICE,
		    pid);

		cocall_or_fail(target, &buf, sizeof(buf), &buf, sizeof(buf));

		/*
		 * Back from the cocall, now running on the callee's thread TB.
		 * This syscall must unborrow us back onto our own thread and
		 * run in our own process context.
		 */
		observed = getpid();

		(void)kill(pid, SIGKILL);
		(void)waitpid(pid, NULL, 0);

		CHERIBSDTEST_VERIFY2(observed == my_pid,
		    "unborrow returned wrong pid: got %d, expected %d",
		    observed, my_pid);

		cheribsdtest_success();
	}
}

#endif /* !CHERIBSD_C18N_TESTS */

/* Excluded under c18n: a separate cocall fast-path issue causes SIGILL. */
#ifndef CHERIBSD_C18N_TESTS

/*
 * Caller-side lookup for the multi-client dispatches: wait for the callee to
 * coregister SERVICE, then return its target.  These dispatches run as coexec
 * children that report via exit status, so this reports with err(3) rather
 * than cheribsdtest_failure_*(), which only works in the test-body process.
 *
 * Unlike wait_for_service(), there is no worker pid to watch -- the
 * callee is a sibling chosen by a coregister race -- so the spin has no
 * liveness escape if the callee never registers.
 */
static void *
child_wait_for_service(const char *service)
{
	void *target;
	int error;

	if (cosetup(COSETUP_COCALL) != 0)
		err(EX_OSERR, "cosetup_cocall");

	while ((error = colookup(service, &target)) != 0 && errno == ESRCH)
		;
	if (error != 0)
		err(EX_OSERR, "colookup");

	return (target);
}

/*
 * Two caller-side roles shared by the multi-client tests, each taking an
 * optional barrier (pass NULL to skip it).  wait_then_check_pid() waits until
 * released, then its trigger getpid() reports via exit status whether it saw
 * its own pid.  release_then_hold_thread() lowers the barrier to release a
 * peer, then spins to hold its borrowed thread without ever syscalling.  The
 * barrier is touched with plain loads/stores only: a syscall would unborrow us
 * and close the window the test holds open.
 */
static void __dead2
wait_then_check_pid(volatile int *barrier, pid_t my_pid)
{
	while (barrier != NULL && *barrier)
		;
	exit(getpid() == my_pid ? 0 : EX_SOFTWARE);
}

static void __dead2
release_then_hold_thread(volatile int *release)
{
	if (release != NULL)
		*release = 0;
	for (;;)
		;
}

/*
 * A test's coexec children sort themselves into roles by racing to
 * coregister SERVICE: the winner is callee B and should run its worker
 * (which never returns); the losers are callers.
 */
static bool
coregister_wins(const char *service)
{
	if (cosetup(COSETUP_COACCEPT) != 0)
		err(EX_OSERR, "cosetup_coaccept");

	if (coregister(service, NULL) == 0)
		return (true);

	if (errno != EEXIST)
		err(EX_OSERR, "coregister");

	return (false);
}

/*
 * Role the callee assigns each caller by arrival order, through the cocall
 * buffer: the first caller it replies to is the incumbent, left hosted on B's
 * thread TB; the second is the newcomer, cocalling while TB is still borrowed.
 */
#define	CO_INCUMBENT	1
#define	CO_NEWCOMER	2

/* Verdict pending_callee_worker relays to the newcomer. */
#define	CO_PASS		3
#define	CO_FAIL		4

/* Carries the release barrier and the assigned role from callee to caller. */
struct caller_msg {
	volatile int	*barrier;
	int		 role;
};

#define	COLOCATION_SERVED_INCUMBENT_SERVICE	"colocation_served_incumbent"

static void __dead2
served_incumbent_worker(void)
{
	/*
	 * Barrier the incumbent waits on and the newcomer lowers, touched with
	 * plain loads/stores only: a syscall would unborrow and close the
	 * window the test must hold open.  It starts raised; the newcomer
	 * lowers it once its cocall has landed.
	 */
	static volatile int barrier = 1;

	struct caller_msg msg;
	int served;

	served = 0;
	for (;;) {
		msg.barrier = &barrier;
		/*
		 * The first coaccept parks and sends no reply, so served == 1
		 * is the first caller actually replied to -- the incumbent.
		 */
		msg.role = (served == 1) ? CO_INCUMBENT : CO_NEWCOMER;

		if (coaccept(NULL, &msg, sizeof(msg), &msg, sizeof(msg)) < 0)
			err(EX_OSERR, "coaccept");

		/*
		 * This syscall is the unborrow that moves B back onto its own
		 * thread TB, so B's next coaccept hands the caller's context
		 * onto TB.  getpid() is just an arbitrary cheap syscall.
		 */
		(void)getpid();

		served++;
	}
}

static void
colocation_served_incumbent_dispatch(void)
{
	struct caller_msg msg;
	void *target;
	pid_t my_pid;

	if (coregister_wins(COLOCATION_SERVED_INCUMBENT_SERVICE))
		served_incumbent_worker();	/* callee B */

	target = child_wait_for_service(COLOCATION_SERVED_INCUMBENT_SERVICE);

	/* Cache our pid before the cocall borrows us. */
	my_pid = getpid();

	msg.barrier = NULL;
	msg.role = 0;
	if (cocall(target, &msg, sizeof(msg), &msg, sizeof(msg)) < 0)
		err(EX_OSERR, "cocall");

	if (msg.role == CO_INCUMBENT)
		wait_then_check_pid(msg.barrier, my_pid);
	else
		release_then_hold_thread(msg.barrier);
}

/*
 * Driver shared by the multi-process reproducers below.  Fork nchildren
 * colocated children that coexec and sort themselves into roles via coregister,
 * then wait for the lone child that exits with the verdict (the others loop or
 * spin forever as callees/holders) and tear them down.  Exit status zero is a
 * pass; non-zero means the cocall was mishandled.
 */
static void
colocation_coexec_run(int nchildren, const char *failmsg)
{
	pid_t pids[8], pid;
	int i, res;

	CHERIBSDTEST_VERIFY2(nchildren <= (int)nitems(pids),
	    "nchildren %d too large", nchildren);

	for (i = 0; i < nchildren; i++) {
		pids[i] = fork();
		if (pids[i] == -1)
			cheribsdtest_failure_err("fork %d", i);

		if (pids[i] == 0)
			cheribsdtest_coexec_child();
	}

	pid = wait(&res);

	/*
	 * Tear down the survivors.  Skip the child wait() already reaped -- its
	 * pid may since have been recycled.
	 */
	for (i = 0; i < nchildren; i++) {
		if (pids[i] == pid)
			continue;

		(void)kill(pids[i], SIGKILL);
		(void)waitpid(pids[i], NULL, 0);
	}

	CHERIBSDTEST_VERIFY2(WIFEXITED(res) && WEXITSTATUS(res) == 0,
	    "%s: child pid %d status 0x%x", failmsg, pid, res);

	cheribsdtest_success();
}

/*
 * Three colocated processes share one vmspace: B is the callee (the coregister
 * winner), A and C are callers, with kernel threads TA, TB, TC.  A is the
 * incumbent (the first caller B serves, left hosted on TB); C is the newcomer
 * (the second, cocalling while TB is still borrowed).
 *
 *	A>B
 *	B@
 *	A<B	=> {TB->A}
 *	C>B	=> {TB->A, TC->B, (C)}
 *	B@
 *	C<B
 *	A@	|= {TA->A}
 *
 * The newcomer has been served (C<B) before the incumbent's syscall.  Property
 * under test: the incumbent's later syscall must still unborrow back onto its
 * own thread TA.
 */
CHERIBSDTEST(colocation_served_incumbent_unborrow,
    "After a newcomer's cocall to the same callee has been served, the "
    "incumbent still hosted on the callee's thread must unborrow its later "
    "syscall back to its own thread (multi-client cocall)",
    .ct_child_func = colocation_served_incumbent_dispatch,
    .ct_xfail_reason =
	"Multi-client cocall is not yet supported: the newcomer's cocall "
	"overwrites the incumbent's borrow record")
{
	colocation_coexec_run(3, "incumbent saw the wrong pid");
}

#define	COLOCATION_PENDING_CALLEE_SERVICE	"colocation_pending_callee"

static void __dead2
pending_callee_worker(void)
{
	intcap_t buf;
	pid_t real_pid, observed;
	int served;

	real_pid = getpid();

	served = 0;
	buf = CO_INCUMBENT;
	for (;;) {
		if (coaccept(NULL, &buf, sizeof(buf), &buf, sizeof(buf)) < 0)
			err(EX_OSERR, "coaccept");

		served++;

		/*
		 * Serving the incumbent, this getpid() is the unborrow that
		 * leaves it running on B's thread; serving the newcomer, it is
		 * the syscall under test.
		 */
		observed = getpid();

		if (served == 1)
			buf = CO_INCUMBENT;
		else
			buf = (observed == real_pid) ? CO_PASS : CO_FAIL;
	}
}

static void
colocation_pending_callee_dispatch(void)
{
	intcap_t buf;
	void *target;

	if (coregister_wins(COLOCATION_PENDING_CALLEE_SERVICE))
		pending_callee_worker();	/* callee B */

	target = child_wait_for_service(COLOCATION_PENDING_CALLEE_SERVICE);

	buf = 0;
	if (cocall(target, &buf, sizeof(buf), &buf, sizeof(buf)) < 0)
		err(EX_OSERR, "cocall");

	switch ((int)buf) {
	case CO_INCUMBENT:
		release_then_hold_thread(NULL);
	case CO_PASS:
	case CO_FAIL:
		exit((int)buf == CO_PASS ? 0 : EX_SOFTWARE);
	default:
		errx(EX_SOFTWARE, "unexpected verdict %d", (int)buf);
	}
}

/*
 * Three colocated processes share one vmspace: B is the callee (the coregister
 * winner), A and C are callers, with kernel threads TA, TB, TC.  A is the
 * incumbent (the first caller B serves, left hosted on TB); C is the newcomer
 * (the second, cocalling while TB is still borrowed).
 *
 *	A>B
 *	B@
 *	A<B	=> {TB->A}
 *	C>B	=> {TB->A, TC->B, (C)}
 *	B@	|= {TB->B}
 *
 * The newcomer's cocall is still pending (no C<B).  Property under test: the
 * callee's own syscall while serving the newcomer must unborrow B back onto
 * its home thread TB and run in B's process context, which requires evicting
 * the incumbent holding TB.
 */
CHERIBSDTEST(colocation_pending_callee_unborrow,
    "A callee serving a newcomer's cocall must reclaim its borrowed home "
    "thread (evicting the incumbent that holds it) so its own syscalls run "
    "in the correct process context (multi-client cocall)",
    .ct_child_func = colocation_pending_callee_dispatch,
    .ct_xfail_reason =
	"Multi-client cocall is not yet supported: the callee's home thread is "
	"borrowed by the incumbent with no logic to evict it")
{
	/*
	 * XXX: the stranded survivors can't be torn down cleanly -- killing
	 * them hangs or panics the kernel (kill-order dependent, a separate
	 * bug) -- so the test never reaches the verdict check.
	 */
	colocation_coexec_run(3, "callee saw the wrong pid");
}

#define	COLOCATION_PENDING_INCUMBENT_SERVICE	"colocation_pending_incumbent"

static void __dead2
pending_incumbent_worker(void)
{
	static volatile int barrier = 1;

	struct caller_msg msg;
	int served;

	served = 0;
	for (;;) {
		msg.barrier = &barrier;
		msg.role = (served == 1) ? CO_INCUMBENT : CO_NEWCOMER;

		if (coaccept(NULL, &msg, sizeof(msg), &msg, sizeof(msg)) < 0)
			err(EX_OSERR, "coaccept");

		if (served == 0) {
			/*
			 * Serving the incumbent: this getpid() is the
			 * unborrow that moves B home to TB, so B's next
			 * coaccept hands the incumbent's context onto TB.
			 */
			(void)getpid();
			served++;
		} else {
			/*
			 * Serving the newcomer: release the incumbent
			 * with a plain store (no syscall, so no unborrow
			 * of our own) and never reach the next coaccept,
			 * so the newcomer stays blocked in its cocall
			 * while the incumbent unborrows.
			 */
			barrier = 0;
			for (;;)
				;
		}
	}
}

static void
colocation_pending_incumbent_dispatch(void)
{
	struct caller_msg msg;
	void *target;
	pid_t my_pid;

	if (coregister_wins(COLOCATION_PENDING_INCUMBENT_SERVICE))
		pending_incumbent_worker();	/* callee B */

	target = child_wait_for_service(COLOCATION_PENDING_INCUMBENT_SERVICE);

	/* Cache our pid before the cocall borrows us. */
	my_pid = getpid();

	msg.barrier = NULL;
	msg.role = 0;
	if (cocall(target, &msg, sizeof(msg), &msg, sizeof(msg)) < 0)
		err(EX_OSERR, "cocall");

	/*
	 * Only the incumbent returns from its cocall (B replies to it on the
	 * next coaccept); the newcomer's cocall never gets a reply, so it
	 * blocks here forever and is torn down as a survivor.
	 */
	if (msg.role == CO_INCUMBENT)
		wait_then_check_pid(msg.barrier, my_pid);
	else
		release_then_hold_thread(msg.barrier);
}

/*
 * Three colocated processes share one vmspace: B is the callee (the coregister
 * winner), A and C are callers, with kernel threads TA, TB, TC.  A is the
 * incumbent (the first caller B serves, left hosted on TB); C is the newcomer
 * (the second, cocalling while TB is still borrowed).
 *
 *	A>B
 *	B@
 *	A<B	=> {TB->A}
 *	C>B	=> {TB->A, TC->B, (C)}
 *	A@	|= {TA->A}
 *
 * Unlike colocation_served_incumbent_unborrow, the incumbent unborrows while
 * the newcomer is still blocked in its cocall -- there is no C<B before A@.
 *
 * Property under test: a newcomer whose cocall is still pending must not
 * prevent the incumbent's syscall from unborrowing back to its own thread.
 */
CHERIBSDTEST(colocation_pending_incumbent_unborrow,
    "When a newcomer's cocall to the same callee is still pending while the "
    "incumbent is hosted on the callee's thread, the incumbent's syscall must "
    "still unborrow back to its own thread (multi-client cocall)",
    .ct_child_func = colocation_pending_incumbent_dispatch,
    .ct_xfail_reason =
	"Multi-client cocall is not yet supported: the newcomer's cocall "
	"overwrites the incumbent's borrow record")
{
	colocation_coexec_run(3, "incumbent saw the wrong pid");
}

#define	COLOCATION_SERVED_NEWCOMER_SERVICE	"colocation_served_newcomer"

static void __dead2
served_newcomer_worker(void)
{
	intcap_t buf;
	int served;

	served = 0;
	for (;;) {
		if (coaccept(NULL, &buf, sizeof(buf), &buf, sizeof(buf)) < 0)
			err(EX_OSERR, "coaccept");

		served++;

		/*
		 * served == 1: serving the incumbent; this getpid() unborrows
		 * B home to TB so the reply hands the incumbent's context onto
		 * TB.  served == 2: serving the newcomer; this getpid() is the
		 * eviction that must reclaim TB from the incumbent.
		 */
		(void)getpid();

		if (served == 1)
			buf = CO_INCUMBENT;
		else
			buf = CO_NEWCOMER;
	}
}

static void
colocation_served_newcomer_dispatch(void)
{
	intcap_t buf;
	void *target;
	pid_t my_pid;

	if (coregister_wins(COLOCATION_SERVED_NEWCOMER_SERVICE))
		served_newcomer_worker();	/* callee B */

	target = child_wait_for_service(COLOCATION_SERVED_NEWCOMER_SERVICE);

	/* Cache our pid before the cocall borrows us. */
	my_pid = getpid();

	buf = 0;
	if (cocall(target, &buf, sizeof(buf), &buf, sizeof(buf)) < 0)
		err(EX_OSERR, "cocall");

	switch ((int)buf) {
	case CO_INCUMBENT:
		release_then_hold_thread(NULL);
	case CO_NEWCOMER:
		wait_then_check_pid(NULL, my_pid);
	default:
		errx(EX_SOFTWARE, "unexpected role %d", (int)buf);
	}
}

/*
 * Three colocated processes share one vmspace: B is the callee (the coregister
 * winner), A and C are callers, with kernel threads TA, TB, TC.  A is the
 * incumbent (the first caller B serves, left hosted on TB); C is the newcomer
 * (the second, cocalling while TB is still borrowed).
 *
 *	A>B
 *	B@
 *	A<B	=> {TB->A}
 *	C>B	=> {TB->A, TC->B, (C)}
 *	B@	=> {TA->A, TB->B}
 *	C<B	=> {TB->C}
 *	C@	|= {TC->C}
 *
 * The newcomer completes its own round trip (C<B).  Property under test: the
 * newcomer's own syscall must then unborrow it back onto its own thread TC and
 * run in its own process context.
 */
CHERIBSDTEST(colocation_served_newcomer_unborrow,
    "After a newcomer's cocall to the same callee is served while the "
    "incumbent is hosted on the callee's thread, the newcomer must unborrow "
    "its own later syscall back to its own thread (multi-client cocall)",
    .ct_child_func = colocation_served_newcomer_dispatch,
    .ct_xfail_reason =
	"Multi-client cocall is not yet supported: the callee cannot reclaim "
	"its home thread to serve the newcomer")
{
	/*
	 * XXX: like colocation_pending_callee_unborrow, the stranded
	 * survivors can't be torn down cleanly -- killing them hangs or
	 * panics the kernel (kill-order dependent, a separate bug) -- so the
	 * test never reaches the verdict check.
	 */
	colocation_coexec_run(3, "newcomer saw the wrong pid");
}

#endif /* !CHERIBSD_C18N_TESTS */

#if defined(__aarch64__)
/*
 * Tests for callee-saved register preservation across the cocall
 * fast-path domain transition.  Each test loads marker values into
 * a set of registers, drives a cocall, and verifies what survived.
 */

#define	COLOCATION_REGTEST_SERVICE	"colocation_register"

static void
colocation_register_worker(void)
{
	intcap_t buf = 0;

	if (cosetup(COSETUP_COACCEPT) != 0)
		err(EX_OSERR, "cosetup");

	if (coregister(COLOCATION_REGTEST_SERVICE, NULL) != 0)
		err(EX_OSERR, "coregister");

	for (;;) {
		if (coaccept(NULL, &buf, sizeof(buf), &buf,
		    sizeof(buf)) < 0)
			err(EX_OSERR, "coaccept");
	}
}

/*
 * Compare a single named capability (e.g., "CTPIDR_EL0") against an expected
 * value using exact tag/bounds/perms/address equality.  With fatal=true,
 * errx on mismatch; with fatal=false, return false instead.  Returns true
 * on a match.
 */
static bool
check_named_cap_match(const char *name, void *want, void *got,
    const char *across, bool fatal)
{
	if (__builtin_cheri_equal_exact(got, want))
		return (true);

	if (!fatal)
		return (false);

	cheribsdtest_failure_errx(
	    "%s not preserved across %s: got=%#p want=%#p",
	    name, across, got, want);
}

/* Excluded under c18n: a separate cocall fast-path issue causes SIGILL. */
#ifndef CHERIBSD_C18N_TESTS

/* Defined in arm64/cheribsdtest_colocation_asm.S. */
void	fp_register_check_via_cocall(void *target,
	    const void *markers, void *vals);

void	gp_register_check_via_cocall(void *target,
	    void * const *markers, void **vals);

void	fp_register_check_via_coaccept(void *cookiep,
	    const void *markers, void *vals);

void	gp_register_check_via_coaccept(void *cookiep,
	    void * const *markers, void **vals);

/*
 * Full-width FP marker slot for q8-q15.  Splitting the 128-bit q-reg
 * into two uint64_t fields lets the markers carry different values
 * in the low half (which aliases d8-d15, the AAPCS callee-saved
 * subset) and the high half (only reached by SIMD code).  A switcher
 * bug that only saves and restores the low 64 bits -- i.e., treats
 * the register as a d-reg -- would leave the high sentinel stale,
 * which the test catches.  __aligned(16) lets the asm load and store
 * the slot with a single ldp/stp q-reg pair instruction.
 */
struct fp_q_slot {
	uint64_t	low;
	uint64_t	high;
} __aligned(16);

/*
 * Build 8 distinct full-width q-register markers.  Low half holds the
 * IEEE 754 bit pattern of (i + 1.0) so the low-half check matches the
 * "d8 = 1.0 .. d15 = 8.0" semantic of the original test; high half
 * holds a 0xDEADBEEF-tagged sentinel so any switcher bug specific to
 * the upper 64 bits of v8-v15 surfaces distinctly.
 */
static void
build_fp_q_markers(struct fp_q_slot markers[8])
{
	int i;

	for (i = 0; i < 8; i++) {
		double d = (double)(i + 1);
		uint64_t bits;
		memcpy(&bits, &d, sizeof(bits));
		markers[i].low = bits;
		markers[i].high = 0xDEADBEEF00000001ULL + i;
	}
}

#define	GP_MARKER_COUNT		10	/* c19-c28 */
#define	GP_MARKER_STRIDE	16
#define	GP_MARKER_BUF_SIZE	(GP_MARKER_COUNT * GP_MARKER_STRIDE)

/*
 * Build GP_MARKER_COUNT distinct tagged-capability markers backed by
 * buf[].  The markers differ in address (GP_MARKER_STRIDE apart) and
 * all carry buf's tag, bounds and permissions, so the comparison
 * checks the whole capability, not just the address.  buf must span
 * GP_MARKER_BUF_SIZE bytes.
 */
static void
build_gp_cap_markers(void *markers[GP_MARKER_COUNT], char *buf)
{
	int i;

	for (i = 0; i < GP_MARKER_COUNT; i++)
		markers[i] = &buf[i * GP_MARKER_STRIDE];
}

/*
 * Compare an observed snapshot of q8-q15 (full 128-bit, both low and
 * high halves) against the markers.  across is a short phrase
 * describing the round-trip path under test (e.g., "cocall" /
 * "coaccept resumption") that gets spliced into the failure message.
 * With fatal=true, errx on the first mismatch; with fatal=false, just
 * return false instead.  Returns true if every slot matches.
 */
static bool
check_q_match(const struct fp_q_slot want[8], const struct fp_q_slot got[8],
    const char *across, bool fatal)
{
	int i;

	for (i = 0; i < 8; i++) {
		if (got[i].low == want[i].low && got[i].high == want[i].high)
			continue;

		if (!fatal)
			return (false);

		cheribsdtest_failure_errx(
		    "q%d not preserved across %s: "
		    "got={0x%lx, 0x%lx} want={0x%lx, 0x%lx}",
		    i + 8, across,
		    got[i].low, got[i].high,
		    want[i].low, want[i].high);
	}

	return (true);
}

/*
 * Compare a single named scalar register (e.g., "FPCR", "FPSR")
 * against an expected value.  With fatal=true, errx on mismatch;
 * with fatal=false, return false instead.  Returns true on a match.
 */
static bool
check_named_scalar_match(const char *name, unsigned long want,
    unsigned long got, const char *across, bool fatal)
{
	if (got == want)
		return (true);

	if (!fatal)
		return (false);

	cheribsdtest_failure_errx(
	    "%s not preserved across %s: got=0x%lx want=0x%lx",
	    name, across, got, want);
}

static void
load_fp_status_control(unsigned long fpcr, unsigned long fpsr)
{
	__asm__ __volatile__ (
	    "msr fpcr, %0\n\t"
	    "msr fpsr, %1"
	    : : "r" (fpcr), "r" (fpsr));
}

static void
read_fp_status_control(unsigned long *fpcr, unsigned long *fpsr)
{
	__asm__ __volatile__ (
	    "mrs %0, fpcr\n\t"
	    "mrs %1, fpsr"
	    : "=r" (*fpcr), "=r" (*fpsr));
}

static void *
read_ctpidr_el0(void)
{
	void *v;

	__asm__ __volatile__ ("mrs %0, ctpidr_el0" : "=C" (v));
	return (v);
}

/*
 * Compare an observed snapshot of c19-c28 against the markers using
 * exact tag/bounds/perms/address equality.  across is a short phrase
 * describing the round-trip path under test (e.g., "cocall" /
 * "coaccept resumption") that gets spliced into the failure message.
 * With fatal=true, errx on the first mismatch; with fatal=false,
 * just return false instead.  Returns true if every slot matches.
 */
static bool
check_caps_match(void * const want[GP_MARKER_COUNT],
    void * const got[GP_MARKER_COUNT], const char *across, bool fatal)
{
	int i;

	for (i = 0; i < GP_MARKER_COUNT; i++) {
		if (__builtin_cheri_equal_exact(got[i], want[i]))
			continue;

		if (!fatal)
			return (false);

		cheribsdtest_failure_errx(
		    "c%d not preserved across %s: got=%#p want=%#p",
		    i + 19, across, got[i], want[i]);
	}

	return (true);
}

/*
 * GP-callee coaccept response: 10 markers the worker chose plus the
 * 10 c19-c28 values it observed on resumption.  The worker derives
 * its markers from its own stack, so the caller doesn't know what
 * to compare against unless the worker ships the markers back
 * alongside the snapshot.  Compared in the caller-side test with
 * __builtin_cheri_equal_exact.
 */
struct colocation_gp_cap_response {
	void	*markers[GP_MARKER_COUNT];
	void	*vals[GP_MARKER_COUNT];
};

/*
 * FP-callee coaccept response: same shape but with 8 q-register slots
 * instead of 10 capabilities.
 */
struct colocation_fp_q_response {
	struct fp_q_slot	markers[8];
	struct fp_q_slot	vals[8];
};

/*
 * Workers for the callee-side register-preservation tests.  Each
 * mirrors its caller-side counterpart.  The worker loads markers in
 * its own callee-saved registers BEFORE its first coaccept, then on
 * resumption reads them back and ships the result to the caller via
 * the second coaccept's response buffer.  Coroutine-shaped semantics:
 * the worker should observe its own pre-coaccept state on resumption.
 *
 * For FP and GP markers the load-coaccept-read sequence runs in a
 * pure-asm helper to keep the compiler from spilling/reloading the
 * tracked registers around the call.
 */
static void
colocation_callee_saved_fp_worker(void)
{
	intcap_t recv_buf = 0;
	struct colocation_fp_q_response response;

	if (cosetup(COSETUP_COACCEPT) != 0)
		err(EX_OSERR, "cosetup");

	if (coregister(COLOCATION_REGTEST_SERVICE, NULL) != 0)
		err(EX_OSERR, "coregister");

	build_fp_q_markers(response.markers);

	fp_register_check_via_coaccept(NULL, response.markers, response.vals);

	if (coaccept(NULL, &response, sizeof(response), &recv_buf,
	    sizeof(recv_buf)) < 0)
		err(EX_OSERR, "coaccept");

	err(EX_SOFTWARE, "Second coaccept returned.");
}

static void
colocation_callee_saved_gp_worker(void)
{
	intcap_t recv_buf = 0;
	struct colocation_gp_cap_response response;
	char buf[GP_MARKER_BUF_SIZE] __aligned(16);

	if (cosetup(COSETUP_COACCEPT) != 0)
		err(EX_OSERR, "cosetup");

	if (coregister(COLOCATION_REGTEST_SERVICE, NULL) != 0)
		err(EX_OSERR, "coregister");

	build_gp_cap_markers(response.markers, buf);

	gp_register_check_via_coaccept(NULL, response.markers, response.vals);

	if (coaccept(NULL, &response, sizeof(response), &recv_buf,
	    sizeof(recv_buf)) < 0)
		err(EX_OSERR, "coaccept");

	err(EX_SOFTWARE, "Second coaccept returned.");
}

static void
colocation_fp_status_control_worker(void)
{
	intcap_t recv_buf = 0;
	unsigned long fpcs_vals[2];

	if (cosetup(COSETUP_COACCEPT) != 0)
		err(EX_OSERR, "cosetup");

	if (coregister(COLOCATION_REGTEST_SERVICE, NULL) != 0)
		err(EX_OSERR, "coregister");

	/*
	 * The load+coaccept+read sequence must stay FP-free -- any FP
	 * arithmetic would set FPSR flags and pollute the result.  No
	 * call between here and the read does FP work.
	 */
	load_fp_status_control(FPCR_PRESERVATION_MARKER,
	    FPSR_PRESERVATION_MARKER);

	if (coaccept(NULL, &recv_buf, sizeof(recv_buf), &recv_buf,
	    sizeof(recv_buf)) < 0)
		err(EX_OSERR, "coaccept");

	read_fp_status_control(&fpcs_vals[0], &fpcs_vals[1]);

	if (coaccept(NULL, fpcs_vals, sizeof(fpcs_vals), &recv_buf,
	    sizeof(recv_buf)) < 0)
		err(EX_OSERR, "coaccept");

	err(EX_SOFTWARE, "Second coaccept returned.");
}

CHERIBSDTEST(colocation_callee_saved_fp_via_cocall,
    "Check AArch64 callee-saved FP regs (q8-q15) survive cocall round-trips",
    .ct_child_func = colocation_register_worker)
{
	void *target;
	struct fp_q_slot markers[8];
	struct fp_q_slot vals[8];
	pid_t pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGTEST_SERVICE, pid);

		build_fp_q_markers(markers);

		fp_register_check_via_cocall(target, markers, vals);

		check_q_match(markers, vals, "cocall", true);

		cheribsdtest_success();
	}
}

/*
 * End-to-end check on the cocall path (libc cocall + switcher
 * combined).  This test cannot distinguish "the switcher preserves
 * c19-c28" from "the switcher mishandles them but libc cocall's
 * prologue/epilogue saves and restores them around the call" -- but
 * that distinction doesn't really matter for our purposes.  Users of cocall
 * see the end-to-end behaviour, and if anything along the path
 * stops preserving c19-c28 this test will start failing.
 *
 * Markers are tagged capabilities so the test exercises tag, bounds,
 * permissions, and address bits -- any switcher bug that strips a tag,
 * rewrites bounds, or clears permissions would surface.
 */
CHERIBSDTEST(colocation_callee_saved_gp_via_cocall,
    "Check AArch64 callee-saved GP regs (c19-c28) survive cocall round-trips",
    .ct_child_func = colocation_register_worker)
{
	void *target;
	void *markers[GP_MARKER_COUNT];
	void *vals[GP_MARKER_COUNT];
	char buf[GP_MARKER_BUF_SIZE] __aligned(16);
	pid_t pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGTEST_SERVICE, pid);

		build_gp_cap_markers(markers, buf);

		gp_register_check_via_cocall(target, markers, vals);

		check_caps_match(markers, vals, "cocall", true);

		cheribsdtest_success();
	}
}

CHERIBSDTEST(colocation_fp_status_control_via_cocall,
    "Check FPCR/FPSR survive cocall round-trips",
    .ct_child_func = colocation_register_worker)
{
	void *target;
	intcap_t buf = 0;
	pid_t pid;
	unsigned long fpcr_want, fpsr_want, fpcr_got, fpsr_got;

	/*
	 * Pick non-default values that any reasonable program might
	 * legitimately set: FPCR with RMode = 0b01 (round toward
	 * +infinity, bits 22-23) and FPSR with IXC (inexact, bit 4)
	 * and IOC (invalid op, bit 0) sticky flags raised.
	 */
	fpcr_want = FPCR_PRESERVATION_MARKER;
	fpsr_want = FPSR_PRESERVATION_MARKER;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGTEST_SERVICE, pid);

		/*
		 * The load+read pair only measures what the cocall
		 * path does if no FP arithmetic runs in between -- any
		 * FP op would set FPSR flags and pollute the result.
		 * cocall is integer-only, so the assumption holds.
		 */
		load_fp_status_control(fpcr_want, fpsr_want);
		cocall_or_fail(target, &buf, sizeof(buf), &buf, sizeof(buf));
		read_fp_status_control(&fpcr_got, &fpsr_got);

		check_named_scalar_match("FPCR", fpcr_want, fpcr_got, "cocall",
		    true);
		check_named_scalar_match("FPSR", fpsr_want, fpsr_got, "cocall",
		    true);

		cheribsdtest_success();
	}
}

CHERIBSDTEST(colocation_callee_saved_fp_via_coaccept,
    "Check AArch64 callee-saved FP regs (q8-q15) survive coaccept round-trips",
    .ct_child_func = colocation_callee_saved_fp_worker)
{
	void *target;
	struct colocation_fp_q_response response;
	intcap_t send_buf = 0;
	pid_t pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGTEST_SERVICE, pid);

		/*
		 * The worker loaded q8-q15 markers before its first
		 * coaccept; on resumption it snapshots them and returns
		 * both markers and observed values via the second
		 * coaccept's response buffer.
		 */
		cocall_or_fail(target, &send_buf, sizeof(send_buf),
		    &response, sizeof(response));

		check_q_match(response.markers, response.vals,
		    "coaccept resumption", true);

		cheribsdtest_success();
	}
}

CHERIBSDTEST(colocation_callee_saved_gp_via_coaccept,
    "Check AArch64 callee-saved GP regs (c19-c28) survive coaccept round-trips",
    .ct_child_func = colocation_callee_saved_gp_worker)
{
	void *target;
	struct colocation_gp_cap_response response;
	intcap_t send_buf = 0;
	pid_t pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGTEST_SERVICE, pid);

		cocall_or_fail(target, &send_buf, sizeof(send_buf),
		    &response, sizeof(response));

		check_caps_match(response.markers, response.vals,
		    "coaccept resumption", true);

		cheribsdtest_success();
	}
}

CHERIBSDTEST(colocation_fp_status_control_via_coaccept,
    "Check FPCR/FPSR survive coaccept round-trips",
    .ct_child_func = colocation_fp_status_control_worker)
{
	void *target;
	intcap_t send_buf = 0;
	pid_t pid;
	unsigned long fpcs_vals[2];
	unsigned long fpcr_want = FPCR_PRESERVATION_MARKER;
	unsigned long fpsr_want = FPSR_PRESERVATION_MARKER;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGTEST_SERVICE, pid);

		cocall_or_fail(target, &send_buf, sizeof(send_buf),
		    fpcs_vals, sizeof(fpcs_vals));

		check_named_scalar_match("FPCR", fpcr_want, fpcs_vals[0],
		    "coaccept resumption", true);
		check_named_scalar_match("FPSR", fpsr_want, fpcs_vals[1],
		    "coaccept resumption", true);

		cheribsdtest_success();
	}
}

/*
 * CTPIDR_EL0 is the capability TLS pointer; the cocall switcher
 * explicitly saves and restores it.  Snapshot-before-and-after is the
 * only safe pattern: mutating CTPIDR_EL0 to a non-TLS marker would
 * fault any C code that touches errno, _trace_cocall, or stack
 * canaries between the mutation and the restore.  The test catches
 * the case where the switcher's save/restore is missing or broken --
 * caller would resume with the callee's TLS pointer instead of its
 * own, breaking every later TLS access.
 */
struct colocation_ctpidr_response {
	void	*before;
	void	*after;
};

static void
colocation_ctpidr_worker(void)
{
	intcap_t recv_buf = 0;
	struct colocation_ctpidr_response response;

	if (cosetup(COSETUP_COACCEPT) != 0)
		err(EX_OSERR, "cosetup");

	if (coregister(COLOCATION_REGTEST_SERVICE, NULL) != 0)
		err(EX_OSERR, "coregister");

	response.before = read_ctpidr_el0();

	if (coaccept(NULL, &recv_buf, sizeof(recv_buf), &recv_buf,
	    sizeof(recv_buf)) < 0)
		err(EX_OSERR, "coaccept");

	response.after = read_ctpidr_el0();

	if (coaccept(NULL, &response, sizeof(response), &recv_buf,
	    sizeof(recv_buf)) < 0)
		err(EX_OSERR, "coaccept");

	err(EX_SOFTWARE, "Second coaccept returned.");
}

CHERIBSDTEST(colocation_ctpidr_el0_via_cocall,
    "Check CTPIDR_EL0 (capability TLS pointer) survives cocall round-trips",
    .ct_child_func = colocation_register_worker)
{
	void *target;
	void *before, *after;
	intcap_t buf = 0;
	pid_t pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGTEST_SERVICE, pid);

		before = read_ctpidr_el0();
		cocall_or_fail(target, &buf, sizeof(buf), &buf, sizeof(buf));
		after = read_ctpidr_el0();

		check_named_cap_match("CTPIDR_EL0", before, after, "cocall",
		    true);

		cheribsdtest_success();
	}
}

CHERIBSDTEST(colocation_ctpidr_el0_via_coaccept,
    "Check CTPIDR_EL0 (capability TLS pointer) survives coaccept round-trips",
    .ct_child_func = colocation_ctpidr_worker)
{
	void *target;
	struct colocation_ctpidr_response response;
	intcap_t send_buf = 0;
	pid_t pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGTEST_SERVICE, pid);

		cocall_or_fail(target, &send_buf, sizeof(send_buf),
		    &response, sizeof(response));

		check_named_cap_match("CTPIDR_EL0", response.before,
		    response.after, "coaccept resumption", true);

		cheribsdtest_success();
	}
}

/*
 * Direct-switcher (libc-bypass) preservation tests.
 *
 * The via_cocall / via_coaccept tests above exercise the full
 * userspace path: libsys' cocall / coaccept C wrapper -> the
 * _cocall / _coaccept asm trampolines -> switcher.  The trampolines
 * only save c29 and c30 around the blrs, but the cocall / coaccept
 * C wrapper above them is an AAPCS function whose compiler-generated
 * prologue/epilogue spills whichever subset of c19-c28 it happens
 * to use as locals.  A switcher bug that clobbered those particular
 * registers would be silently restored from the wrapper's spill
 * slots on return, and the existing tests would still pass.  Which
 * c19-c28 are masked this way depends on the compiler output, so
 * the existing tests' sensitivity to c19-c28 clobbers is
 * non-uniform.  q8-q15, FPCR, FPSR and CTPIDR_EL0 are not touched
 * by the wrapper or the trampolines, so the existing tests already
 * cover those.
 *
 * The tests below skip the C wrapper.  A pure-asm helper sets
 * the markers, branches into the switcher entry directly via blrs
 * (the same instruction libsys uses), and snapshots the registers
 * on return -- with no AAPCS-compliant intermediate frame between
 * marker load and snapshot.  The main coverage gain is uniform
 * sensitivity to switcher c19-c28 clobbers regardless of compiler
 * spill choices; q8-q15 / FPCR / FPSR / CTPIDR_EL0 are exercised
 * here too to keep the direct path self-contained and future-proof
 * against any save/restore being added to the libsys trampolines.
 *
 * One test per direction (cocall caller / coaccept callee).  Each
 * covers every register the switcher tracks (c19-c28, q8-q15, FPCR,
 * FPSR, CTPIDR_EL0) in one call.  The helper must save, stage and
 * restore the full set regardless of which class is under test, so
 * covering them all in one invocation is free.
 */

/*
 * Combined register snapshot for the direct-switcher tests.  Layout
 * is shared with the asm helper -- offsets are the SR_* constants in
 * arm64/cheribsdtest_colocation_asm.h, and a layout change here must
 * be mirrored there.
 */
struct switcher_regset {
	void			*gp[GP_MARKER_COUNT]; /* c19-c28; offset 0 */
	struct fp_q_slot	fp[8];		/* q8-q15;  offset 160 */
	uint64_t		fpcr;		/* offset 288 */
	uint64_t		fpsr;		/* offset 296 */
	void			*ctpidr_el0;	/* offset 304 */
} __aligned(16);

_Static_assert(__offsetof(struct switcher_regset, gp) == SR_GP_OFF,
    "switcher_regset.gp offset must match SR_GP_OFF");

_Static_assert(__offsetof(struct switcher_regset, fp) == SR_FP_OFF,
    "switcher_regset.fp offset must match SR_FP_OFF");

_Static_assert(__offsetof(struct switcher_regset, fpcr) == SR_FPCR_OFF,
    "switcher_regset.fpcr offset must match SR_FPCR_OFF");

_Static_assert(__offsetof(struct switcher_regset, fpsr) == SR_FPSR_OFF,
    "switcher_regset.fpsr offset must match SR_FPSR_OFF");

_Static_assert(__offsetof(struct switcher_regset, ctpidr_el0) ==
    SR_CTPIDR_OFF,
    "switcher_regset.ctpidr_el0 offset must match SR_CTPIDR_OFF");

ssize_t	switcher_entry_check_direct(void *code, void *data,
	    void *target_or_cookiep,
	    const struct switcher_regset *markers,
	    struct switcher_regset *vals);

static void
build_switcher_regset_markers(struct switcher_regset *r, char *buf)
{
	build_gp_cap_markers(r->gp, buf);
	build_fp_q_markers(r->fp);
	r->fpcr = FPCR_PRESERVATION_MARKER;
	r->fpsr = FPSR_PRESERVATION_MARKER;

	/*
	 * CTPIDR_EL0 marker is a tagged data cap into buf -- not a valid
	 * TLS pointer.  The asm helper restores the real CTPIDR_EL0
	 * before any C code resumes, so the marker only has to survive
	 * the switcher round trip.  The mid-stride offset keeps it
	 * distinct from every GP marker (whole strides into buf), so a
	 * cross-restore between CTPIDR_EL0 and c19-c28 cannot pass
	 * unnoticed; the marker is never dereferenced, so its alignment
	 * does not matter.
	 */
	r->ctpidr_el0 = &buf[GP_MARKER_STRIDE / 2];
}

/* Return whether every class matches, with no diagnostics. */
static bool
switcher_regset_check_silent(const struct switcher_regset *want,
    const struct switcher_regset *got)
{
	return (
	    check_caps_match(want->gp, got->gp, "direct switcher", false) &&
	    check_q_match(want->fp, got->fp, "direct switcher", false) &&
	    check_named_scalar_match("FPCR", want->fpcr, got->fpcr,
		    "direct switcher", false) &&
	    check_named_scalar_match("FPSR", want->fpsr, got->fpsr,
		    "direct switcher", false) &&
	    check_named_cap_match("CTPIDR_EL0", want->ctpidr_el0,
		    got->ctpidr_el0, "direct switcher", false));
}

/*
 * On mismatch the per-class helper fails the test with a
 * per-register diagnostic, so a return means every class matched.
 */
static void
switcher_regset_check_fatal(const struct switcher_regset *want,
    const struct switcher_regset *got)
{
	check_caps_match(want->gp, got->gp, "direct switcher", true);
	check_q_match(want->fp, got->fp, "direct switcher", true);
	check_named_scalar_match("FPCR", want->fpcr, got->fpcr,
	    "direct switcher", true);
	check_named_scalar_match("FPSR", want->fpsr, got->fpsr,
	    "direct switcher", true);
	check_named_cap_match("CTPIDR_EL0", want->ctpidr_el0, got->ctpidr_el0,
	    "direct switcher", true);
}

CHERIBSDTEST(colocation_switcher_cocall_direct,
    "Drive switcher_cocall directly (no libc shim) and check c19-c28, "
    "q8-q15, FPCR, FPSR, CTPIDR_EL0 all survive the round trip",
    .ct_child_func = colocation_register_worker)
{
	void *target;
	void * __capability cocall_code;
	void * __capability cocall_data;
	struct switcher_regset markers, vals;
	char buf[GP_MARKER_BUF_SIZE] __aligned(16);
	ssize_t ret;
	pid_t pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGTEST_SERVICE, pid);

		/*
		 * Mint the sealed cocall code+data pair into local vars via
		 * the raw _cosetup syscall.  libsys's cosetup() wrapper would
		 * stash the pair in TLS globals that aren't exported, so we
		 * can't access them.
		 */
		if (_cosetup(COSETUP_COCALL, &cocall_code, &cocall_data) != 0)
			cheribsdtest_failure_err("_cosetup");

		build_switcher_regset_markers(&markers, buf);

		/*
		 * wait_for_service() only proves the worker has
		 * coregistered; until its first coaccept parks, the
		 * switcher bounces the cocall with EAGAIN -- and on that
		 * exit the markers are still in the registers, so an
		 * unchecked call would snapshot them unchanged and pass
		 * without testing anything.  Retry the window away, as
		 * libc's cocall() does, and fail on any other error.
		 */
		for (;;) {
			ret = switcher_entry_check_direct(cocall_code,
			    cocall_data, target, &markers, &vals);
			if (ret >= 0)
				break;

			if (ret != -EAGAIN) {
				errno = (int)-ret;
				cheribsdtest_failure_err(
				    "switcher_entry_check_direct");
			}

			usleep(1000);
		}

		switcher_regset_check_fatal(&markers, &vals);

		cheribsdtest_success();
	}
}

struct colocation_switcher_response {
	struct switcher_regset	markers;
	struct switcher_regset	vals;
	bool			worker_pass;
};

/*
 * Worker for the coaccept-direct test.  Mirrors the existing
 * gp/fp/ctpidr workers but drives switcher_coaccept directly.  The
 * first coaccept blocks via copark; the second (libc) coaccept ships
 * the markers, post-resume snapshot, and the worker's own pass/fail
 * verdict back to the test runner.  The verdict is authoritative --
 * the markers/vals are shipped only so the runner can print the
 * mismatching registers when the verdict is a failure.
 */
static void
colocation_switcher_coaccept_direct_worker(void)
{
	intcap_t recv_buf = 0;
	struct colocation_switcher_response response;
	void * __capability coaccept_code;
	void * __capability coaccept_data;
	char buf[GP_MARKER_BUF_SIZE] __aligned(16);
	ssize_t ret;

	/*
	 * Populate libsys's TLS with the coaccept pair: the
	 * response-shipping coaccept() at the bottom takes the libsys
	 * path and reads the pair from there.
	 */
	if (cosetup(COSETUP_COACCEPT) != 0)
		err(EX_OSERR, "cosetup");

	/*
	 * Also mint the sealed pair into local vars via the raw
	 * _cosetup syscall.  The kernel creates the SCB once per thread
	 * and reuses it, so this second call just mints another sealed
	 * pair to the same SCB -- both coaccepts here operate on one
	 * control block.
	 */
	if (_cosetup(COSETUP_COACCEPT, &coaccept_code, &coaccept_data) != 0)
		err(EX_OSERR, "_cosetup");

	if (coregister(COLOCATION_REGTEST_SERVICE, NULL) != 0)
		err(EX_OSERR, "coregister");

	build_switcher_regset_markers(&response.markers, buf);

	/*
	 * Drives switcher_coaccept directly; sleeps via copark until a
	 * cocall arrives, snapshots the registers on resumption, and
	 * returns to C.
	 */
	ret = switcher_entry_check_direct(coaccept_code, coaccept_data,
	    NULL, &response.markers, &response.vals);
	if (ret < 0)
		errc(EX_OSERR, (int)-ret, "switcher_entry_check_direct");

	/*
	 * Compare here, before replying, and ship only the verdict:
	 * the values would travel in a cocall reply, and a cocall bug
	 * that cleared capability tags would clear them in markers and
	 * snapshot equally -- the two would still match each other,
	 * and the bug would go unnoticed.
	 */
	response.worker_pass = switcher_regset_check_silent(&response.markers,
	    &response.vals);

	/* Send markers, snapshot and verdict back to the test runner. */
	if (coaccept(NULL, &response, sizeof(response), &recv_buf,
	    sizeof(recv_buf)) < 0)
		err(EX_OSERR, "coaccept");

	err(EX_SOFTWARE, "Second coaccept returned.");
}

CHERIBSDTEST(colocation_switcher_coaccept_direct,
    "Drive switcher_coaccept directly (no libc shim) and check c19-c28, "
    "q8-q15, FPCR, FPSR, CTPIDR_EL0 all survive the round trip",
    .ct_child_func = colocation_switcher_coaccept_direct_worker)
{
	void *target;
	intcap_t send_buf = 0;
	struct colocation_switcher_response response;
	pid_t pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGTEST_SERVICE, pid);

		cocall_or_fail(target, &send_buf, sizeof(send_buf),
		    &response, sizeof(response));

		/*
		 * The worker's verdict is authoritative.  If it reports
		 * failure, rerun the comparison on the received copies to
		 * name the mismatching registers in the test failure; if
		 * those copies compare equal, the cocall reply must have
		 * altered them in a way that hides the mismatch, so report
		 * that instead.
		 */
		if (!response.worker_pass) {
			switcher_regset_check_fatal(&response.markers,
			    &response.vals);
			cheribsdtest_failure_errx(
			    "worker reported switcher "
			    "register-preservation failure but the "
			    "received markers/snapshot compare equal -- "
			    "the cocall reply may be masking the mismatch");
		}

		cheribsdtest_success();
	}
}
#endif /* !CHERIBSD_C18N_TESTS */

#ifdef CHERIBSD_C18N_TESTS
static void *
read_rctpidr_el0(void)
{
	void *v;

	__asm__ __volatile__ ("mrs %0, rctpidr_el0" : "=C" (v));
	return (v);
}

/*
 * RCTPIDR_EL0 mirror of the CTPIDR tests above.  On c18n-enabled
 * purecap builds, rtld writes the TLS pointer into RCTPIDR_EL0
 * rather than CTPIDR_EL0 (see sys/arm64/include/tls.h); compiled
 * C code accesses TLS through RCTPIDR_EL0.  The cocall switcher
 * does NOT save or restore RCTPIDR_EL0 -- it only handles
 * CTPIDR_EL0.  When a fast-path cocall borrows the callee's
 * execution onto the caller's kernel thread, the borrowed
 * worker code therefore runs with the caller's RCTPIDR_EL0 still
 * in place: any TLS access the worker makes reads or writes the
 * caller's TCB.  These tests catch that, and so are only built
 * for the c18n cheribsdtest binary.
 */
struct colocation_rctpidr_response {
	void	*before;
	void	*after;
};

static void
colocation_rctpidr_worker(void)
{
	intcap_t recv_buf = 0;
	struct colocation_rctpidr_response response;

	if (cosetup(COSETUP_COACCEPT) != 0)
		err(EX_OSERR, "cosetup");

	if (coregister(COLOCATION_REGTEST_SERVICE, NULL) != 0)
		err(EX_OSERR, "coregister");

	response.before = read_rctpidr_el0();

	if (coaccept(NULL, &recv_buf, sizeof(recv_buf), &recv_buf,
	    sizeof(recv_buf)) < 0)
		err(EX_OSERR, "coaccept");

	response.after = read_rctpidr_el0();

	if (coaccept(NULL, &response, sizeof(response), &recv_buf,
	    sizeof(recv_buf)) < 0)
		err(EX_OSERR, "coaccept");

	err(EX_SOFTWARE, "Second coaccept returned.");
}

CHERIBSDTEST(colocation_rctpidr_el0_via_cocall,
    "Check RCTPIDR_EL0 (c18n TLS pointer) survives cocall round-trips",
    .ct_child_func = colocation_register_worker,
    .ct_xfail_reason =
	"cocall fast-path switcher currently traps with SIGILL when invoked "
	"from a c18n binary (separate, unidentified switcher bug).  Once that "
	"is fixed this test will pass: the switcher never writes RCTPIDR_EL0, "
	"so the caller's value survives a round-trip unmodified, independently "
	"of any future RCTPIDR save/restore")
{
	void *target;
	void *before, *after;
	intcap_t buf = 0;
	pid_t pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGTEST_SERVICE, pid);

		before = read_rctpidr_el0();
		cocall_or_fail(target, &buf, sizeof(buf), &buf, sizeof(buf));
		after = read_rctpidr_el0();

		check_named_cap_match("RCTPIDR_EL0", before, after, "cocall",
		    true);

		cheribsdtest_success();
	}
}

CHERIBSDTEST(colocation_rctpidr_el0_via_coaccept,
    "Check RCTPIDR_EL0 (c18n TLS pointer) survives coaccept round-trips",
    .ct_child_func = colocation_rctpidr_worker,
    .ct_xfail_reason =
	"cocall fast-path switcher currently traps with SIGILL when invoked "
	"from a c18n binary (separate, unidentified switcher bug), which masks "
	"the failure this test targets.  Once that is fixed this test still "
	"fails: the switcher does not save/restore RCTPIDR_EL0 across the "
	"fast-path borrow, so worker user-mode code runs with the caller's TLS")
{
	void *target;
	struct colocation_rctpidr_response response;
	intcap_t send_buf = 0;
	pid_t pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGTEST_SERVICE, pid);

		cocall_or_fail(target, &send_buf, sizeof(send_buf),
		    &response, sizeof(response));

		check_named_cap_match("RCTPIDR_EL0", response.before,
		    response.after, "coaccept resumption", true);

		cheribsdtest_success();
	}
}

/*
 * User-visible demonstration of the RCTPIDR_EL0 leak.  The previous
 * test catches the bug at the register level; this one shows the
 * data-corruption consequence: TLS writes made by the worker during
 * its borrowed execution end up in the caller's TCB.
 *
 * The caller sets errno to a sentinel before the cocall.  The
 * worker, on resumption, writes a different sentinel to errno --
 * because its RCTPIDR_EL0 still points at the caller's TCB, this
 * write lands in the caller's errno slot, not its own.  After the
 * cocall returns the caller reads errno: if the bug is present,
 * errno is the worker's sentinel.
 *
 * Sentinels are outside the normal errno range (1..ELAST, currently
 * 98) so a stray real errno can't masquerade as the caller's value and
 * mask the corruption.
 */
#define	CALLER_ERRNO_SENTINEL	0x4711
#define	WORKER_ERRNO_SENTINEL	0x5a5a

static void
colocation_errno_leak_worker(void)
{
	intcap_t recv_buf = 0;
	intcap_t response = 0;

	if (cosetup(COSETUP_COACCEPT) != 0)
		err(EX_OSERR, "cosetup");

	if (coregister(COLOCATION_REGTEST_SERVICE, NULL) != 0)
		err(EX_OSERR, "coregister");

	if (coaccept(NULL, &recv_buf, sizeof(recv_buf), &recv_buf,
	    sizeof(recv_buf)) < 0)
		err(EX_OSERR, "coaccept");

	/*
	 * If RCTPIDR_EL0 still holds the caller's TLS pointer, this
	 * errno write lands in the caller's errno, not the worker's.
	 */
	errno = WORKER_ERRNO_SENTINEL;

	/*
	 * The buggy store has already landed in the caller's TCB at
	 * the userspace store above; whatever this coaccept does to
	 * errno -- via libc, syscall stubs, or unborrow -- does not
	 * affect the test's observation.
	 */
	if (coaccept(NULL, &response, sizeof(response), &recv_buf,
	    sizeof(recv_buf)) < 0)
		err(EX_OSERR, "coaccept");

	err(EX_SOFTWARE, "Second coaccept returned.");
}

CHERIBSDTEST(colocation_errno_leak_via_cocall,
    "Check that a worker's TLS writes do not leak into the caller's TCB",
    .ct_child_func = colocation_errno_leak_worker,
    .ct_xfail_reason =
	"cocall fast-path switcher currently traps with SIGILL when invoked "
	"from a c18n binary (separate, unidentified switcher bug), which masks "
	"the failure this test targets.  Once that is fixed this test still "
	"fails: the switcher does not save/restore RCTPIDR_EL0 across the "
	"fast-path borrow, so the worker's errno writes corrupt the caller's "
	"TCB")
{
	void *target;
	int caller_after;
	intcap_t buf = 0;
	pid_t pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGTEST_SERVICE, pid);

		errno = CALLER_ERRNO_SENTINEL;

		cocall_or_fail(target, &buf, sizeof(buf), &buf, sizeof(buf));

		caller_after = errno;

		CHERIBSDTEST_VERIFY2(caller_after == CALLER_ERRNO_SENTINEL,
		    "Caller's errno corrupted across cocall: "
		    "before=0x%x after=0x%x (worker wrote 0x%x)",
		    CALLER_ERRNO_SENTINEL, caller_after,
		    WORKER_ERRNO_SENTINEL);

		cheribsdtest_success();
	}
}
#endif /* CHERIBSD_C18N_TESTS */
#endif /* defined(__aarch64__) */
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
