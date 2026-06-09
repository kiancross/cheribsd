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

#ifdef CHERIBSD_DYNAMIC_TESTS
#include <cheribsdtest_dynamic.h>
#endif

#include "cheribsdtest.h"

#if defined(__aarch64__)
#include "cheribsdtest_colocation_asm.h"
#endif

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

static pid_t colocation_worker;

static void
kill_colocation_worker(void)
{
	(void)kill(colocation_worker, SIGKILL);
	(void)waitpid(colocation_worker, NULL, 0);
}

static void *
wait_for_service(const char *service, pid_t worker)
{
	void *target;
	int error;

	CHERIBSDTEST_VERIFY2(colocation_worker == 0,
	    "wait_for_service() called twice");

	colocation_worker = worker;

	/*
	 * cheribsdtest_success() and the failure functions all call exit(),
	 * so the worker is killed whether the test passes or fails.  A test
	 * that times out gets SIGKILL from cheribsdtest, which skips
	 * atexit(), and leaves the worker.
	 */
	if (atexit(kill_colocation_worker) != 0)
		cheribsdtest_failure_err("atexit");

	if (cosetup(COSETUP_COCALL) != 0)
		cheribsdtest_failure_err("cosetup");

	/*
	 * Spin until the worker registers the service.  The waitpid()
	 * call ends the spin if the worker exits before registering.
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

/* Fail the test unless the cocall succeeds and the reply fills recv_buf. */
static void
cocall_or_fail(void *target, void *send_buf, size_t send_size,
    void *recv_buf, size_t recv_size)
{
	ssize_t received;

	received = cocall(target, send_buf, send_size, recv_buf, recv_size);
	if (received < 0)
		cheribsdtest_failure_err("cocall");

	if ((size_t)received != recv_size)
		cheribsdtest_failure_errx("reply is %zd bytes, want %zu",
		    received, recv_size);
}

/*
 * Excluded under c18n, where a bug causes a cocall to fault.
 */
#ifndef CHERIBSD_C18N_TESTS

static void
burn_cpu(unsigned long iterations)
{
	unsigned long x = 1;

	for (unsigned long i = 0; i < iterations; i++) {
		x = x * 1664525 + 1013904223;

		/* Stop the compiler from removing the loop. */
		asm volatile("" : "+r"(x));
	}
}

static double
user_cpu_time_of(pid_t pid)
{
	struct procstat *ps;
	struct kinfo_proc *kp;
	struct rusage *ru;
	unsigned int count;
	double cpu;

	ps = procstat_open_sysctl();
	if (ps == NULL)
		return (-1);

	kp = procstat_getprocs(ps, KERN_PROC_PID, pid, &count);
	if (kp == NULL || count == 0) {
		procstat_close(ps);
		return (-1);
	}

	ru = &kp[0].ki_rusage;
	cpu = ru->ru_utime.tv_sec + ru->ru_utime.tv_usec * 1e-6;

	procstat_freeprocs(ps, kp);
	procstat_close(ps);

	return (cpu);
}

#define	COLOCATION_CALLEE_CPU_TIME_SERVICE	"colocation_callee_cpu_time"

/*
 * Several statclock ticks of user CPU time.  The kernel splits run time
 * into user and system time by counting ticks, so a burn shorter than a
 * tick can show no user time even when the kernel charges it to the
 * callee.  The ticks beyond the first are a safety margin.
 */
#define	COLOCATION_CALLEE_CPU_TIME_BURN_ITERATIONS	20000000UL

static void
colocation_callee_cpu_time_worker(void)
{
	intcap_t buf = 0;
	ssize_t received;

	if (cosetup(COSETUP_COACCEPT) != 0)
		err(EX_OSERR, "cosetup");

	if (coregister(COLOCATION_CALLEE_CPU_TIME_SERVICE, NULL) != 0)
		err(EX_OSERR, "coregister");

	received = coaccept(NULL, &buf, sizeof(buf), &buf, sizeof(buf));
	if (received < 0)
		err(EX_OSERR, "coaccept");

	burn_cpu(COLOCATION_CALLEE_CPU_TIME_BURN_ITERATIONS);

	received = coaccept(NULL, &buf, sizeof(buf), &buf, sizeof(buf));
	if (received < 0)
		err(EX_OSERR, "coaccept");

	errx(EX_SOFTWARE, "second coaccept returned");
}

CHERIBSDTEST(colocation_callee_cpu_time,
    "Check that user CPU time a callee uses during a cocall is charged to the "
    "callee, not the caller",
    .ct_flags = CT_FLAG_SLOW,
    .ct_child_func = colocation_callee_cpu_time_worker,
    .ct_xfail_reason =
	"The kernel charges CPU time to the process that owns the thread, "
	"even while another process's code runs on it")
{
	void *target;
	double caller_start, callee_start, caller_end, callee_end;
	double caller_delta, callee_delta;
	intcap_t buf = 0;
	pid_t pid, my_pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		my_pid = getpid();

		target = wait_for_service(COLOCATION_CALLEE_CPU_TIME_SERVICE,
		    pid);

		caller_start = user_cpu_time_of(my_pid);
		callee_start = user_cpu_time_of(pid);

		cocall_or_fail(target, &buf, sizeof(buf), &buf, sizeof(buf));

		caller_end = user_cpu_time_of(my_pid);
		callee_end = user_cpu_time_of(pid);

		caller_delta = caller_end - caller_start;
		callee_delta = callee_end - callee_start;

		/*
		 * The 1 ms floor stops a pass when neither delta is large
		 * enough to measure.  Once the kernel charges the burn to
		 * the callee, the caller gains only the user time of its
		 * user_cpu_time_of() calls, well under 1% of the burn.  So
		 * the 100x ratio fails only a fix that still charges the
		 * caller over 1% of the burn.
		 */
		if (callee_delta > 0.001 && callee_delta > caller_delta * 100) {
			cheribsdtest_success();
		} else {
			cheribsdtest_failure_errx(
			    "user CPU time charged to the wrong process: "
			    "caller=%.6fs callee=%.6fs",
			    caller_delta, callee_delta);
		}
	}
}

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

	/* B's syscall while hosted on TA; the reply carries the pid it sees. */
	buf = getpid();

	if (coaccept(NULL, &buf, sizeof(buf), &buf, sizeof(buf)) < 0)
		err(EX_OSERR, "coaccept");

	errx(EX_SOFTWARE, "second coaccept returned");
}

/*
 * Trace notation, used by the tests below:
 *
 *	A>B	A cocalls B.
 *	A<B	B replies to A, through its next coaccept.
 *	X@	X unborrows: the kernel moves X's code back to X's own
 *		thread.  The tests trigger it with a syscall.
 *	TB->A	A's code runs on B's thread TB.
 *	(A)	A is blocked in its cocall.
 *	=>	the state that a step results in, listing only processes
 *		away from home.
 *	|=	the state that the test asserts.
 */

/*
 *	A>B	=> {TA->B, (A)}
 *	B@	|= {TB->B}
 *	A<B	=> {TB->A}
 *	A@	|= {TA->A}
 */
CHERIBSDTEST(colocation_single_client_unborrow,
    "Check that a callee's syscall during a cocall and its caller's next "
    "syscall each run as their own process",
    .ct_child_func = colocation_single_client_worker)
{
	void *target;
	intcap_t buf = 0;
	pid_t pid, my_pid, observed_pid;

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

		CHERIBSDTEST_VERIFY2((pid_t)buf == pid,
		    "callee's unborrow returned wrong pid: got %d, expected %d",
		    (pid_t)buf, pid);

		/* A's first syscall after the reply, while hosted on TB. */
		observed_pid = getpid();

		CHERIBSDTEST_VERIFY2(observed_pid == my_pid,
		    "unborrow returned wrong pid: got %d, expected %d",
		    observed_pid, my_pid);

		cheribsdtest_success();
	}
}

/*
 * A test that panics or hangs the kernel stops the whole run, so these tests
 * are skipped unless CHERIBSDTEST_RUN_PANICS is set.
 */
static const char *
skip_known_panic(const struct cheri_test *ctp __unused)
{
	if (getenv("CHERIBSDTEST_RUN_PANICS") != NULL)
		return (NULL);

	return ("Panics or hangs the kernel; set CHERIBSDTEST_RUN_PANICS to "
	    "run it");
}

/*
 * A test child normally reports its result through ccsp, a page that it
 * shares with the test process.  A coexec child is a new program with no
 * pointer to that page, so cheribsdtest_failure_*() cannot report from it.
 * This function therefore reports errors with err(3), and the test reads
 * them from the child's exit status.
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

static void __dead2
wait_then_check_pid(volatile int *barrier, pid_t my_pid)
{
	/*
	 * The wait makes no syscall, because a syscall would move the caller's
	 * code back to its own thread before the check.
	 */
	while (barrier != NULL && *barrier)
		;
	exit(getpid() == my_pid ? 0 : EX_SOFTWARE);
}

static void __dead2
release_then_hold_thread(volatile int *barrier)
{
	if (barrier != NULL)
		*barrier = 0;

	/*
	 * Only the child that reports the verdict exits, so this caller loops
	 * until its parent kills it.  Sleeping would not work: sleep(3) and
	 * pause(3) make a syscall, which moves the caller's code back to its
	 * own thread and changes the state that the reporting child checks.
	 */
	for (;;)
		;
}

/* True for the one child that wins the race to coregister the service. */
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
 * The multi-client tests run three colocated processes in one vmspace: B is
 * the callee (the coregister winner), and A and C are callers, with kernel
 * threads TA, TB, and TC.  A is the incumbent: the first caller B replies to,
 * left hosted on TB.  C is the newcomer: the second caller, which cocalls B
 * while TB is still borrowed.  B assigns each caller its role through the
 * cocall buffer.  All three children run the test's dispatch function.
 */
enum co_message {
	CO_INCUMBENT = 1,	/* not 0, so an unwritten buffer matches none */
	CO_NEWCOMER,

	/* A verdict that a callee relays to a caller. */
	CO_PASS,
	CO_FAIL,
};

struct caller_message {
	volatile int	*barrier;
	enum co_message	 role;
};

#define	COLOCATION_SERVED_INCUMBENT_SERVICE	"colocation_served_incumbent"

static void __dead2
served_incumbent_worker(void)
{
	/* Lowered by the newcomer once its cocall has returned. */
	static volatile int barrier = 1;

	struct caller_message msg;
	int cocall_count;

	cocall_count = 0;
	for (;;) {
		msg.barrier = &barrier;
		/*
		 * 1, not 0: coaccept() replies to the previous call, so the
		 * first caller gets its reply from the second coaccept().
		 */
		msg.role = (cocall_count == 1) ? CO_INCUMBENT : CO_NEWCOMER;

		if (coaccept(NULL, &msg, sizeof(msg), &msg, sizeof(msg)) < 0)
			err(EX_OSERR, "coaccept");

		/*
		 * Any syscall would do.  It moves B's code back to its own
		 * thread TB, where B then replies.
		 */
		(void)getpid();

		cocall_count++;
	}
}

static void
colocation_served_incumbent_dispatch(void)
{
	struct caller_message msg;
	void *target;
	pid_t my_pid;

	if (coregister_wins(COLOCATION_SERVED_INCUMBENT_SERVICE))
		served_incumbent_worker();	/* callee B */

	target = child_wait_for_service(COLOCATION_SERVED_INCUMBENT_SERVICE);

	my_pid = getpid();

	msg.barrier = NULL;
	msg.role = 0;
	if (cocall(target, &msg, sizeof(msg), &msg, sizeof(msg)) < 0)
		err(EX_OSERR, "cocall");

	if (msg.role == CO_INCUMBENT)
		wait_then_check_pid(msg.barrier, my_pid);	/* A */
	else
		release_then_hold_thread(msg.barrier);		/* C */
}

/* The reaped child's pid may since have been recycled, so skip it. */
static void
kill_colocation_children(const pid_t *children, int nchildren,
    pid_t reaped_child)
{
	int i;

	for (i = 0; i < nchildren; i++) {
		if (children[i] == reaped_child)
			continue;

		(void)kill(children[i], SIGKILL);
		(void)waitpid(children[i], NULL, 0);
	}
}

/*
 * Forks nchildren that coexec into this vmspace and run the test's child
 * function.  Exactly one child exits, with the verdict: status zero passes.
 * If the test passes, the rest are killed.  If it fails, they are left
 * running, because killing a colocated process during a cocall can hang or
 * panic the kernel before cheribsdtest reports the verdict.
 */
static void
colocation_coexec_run(int nchildren, const char *failure_message)
{
	pid_t children[8], reaped_child;
	int i, status;

	CHERIBSDTEST_VERIFY2(nchildren <= (int)nitems(children),
	    "nchildren %d too large", nchildren);

	for (i = 0; i < nchildren; i++) {
		children[i] = fork();
		if (children[i] == -1)
			cheribsdtest_failure_err("fork %d", i);

		if (children[i] == 0)
			cheribsdtest_coexec_child();
	}

	reaped_child = wait(&status);

	CHERIBSDTEST_VERIFY2(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "%s: child pid %d status 0x%x", failure_message,
	    reaped_child, status);

	kill_colocation_children(children, nchildren, reaped_child);
	cheribsdtest_success();
}

/*
 *	A>B
 *	B@
 *	A<B	=> {TB->A}
 *	C>B	=> {TB->A, TC->B, (C)}
 *	B@
 *	C<B
 *	A@	|= {TA->A}
 *
 * The newcomer has been served (C<B) before the incumbent's syscall.  Property
 * under test: the incumbent's later syscall still unborrows it back onto its
 * own thread TA.
 */
CHERIBSDTEST(colocation_served_incumbent_unborrow,
    "Check that, after a second caller has been served by the same callee, "
    "the first caller's next syscall runs on its own thread as itself "
    "(multi-client cocall)",
    .ct_child_func = colocation_served_incumbent_dispatch,
    .ct_check_skip = skip_known_panic,
    .ct_xfail_reason =
	"Multi-client cocall is not yet supported: a second caller's cocall "
	"clears the first caller's borrow record")
{
	colocation_coexec_run(3, "incumbent saw the wrong pid");
}

#define	COLOCATION_PENDING_CALLEE_SERVICE	"colocation_pending_callee"

static void __dead2
pending_callee_worker(void)
{
	intcap_t buf;
	pid_t my_pid, observed_pid;
	int cocall_count;

	my_pid = getpid();

	cocall_count = 0;
	buf = CO_INCUMBENT;
	for (;;) {
		if (coaccept(NULL, &buf, sizeof(buf), &buf, sizeof(buf)) < 0)
			err(EX_OSERR, "coaccept");

		cocall_count++;

		/*
		 * Serving A, this moves B back to TB before the reply.  Serving
		 * C, B runs on TC while TB hosts A, so the kernel must evict A
		 * to move B back, and the syscall must then run as B.
		 */
		observed_pid = getpid();

		if (cocall_count == 1)
			buf = CO_INCUMBENT;
		else
			buf = (observed_pid == my_pid) ? CO_PASS : CO_FAIL;
	}
}

static void
colocation_pending_callee_dispatch(void)
{
	intcap_t buf;
	void *target;
	pid_t my_pid;

	if (coregister_wins(COLOCATION_PENDING_CALLEE_SERVICE))
		pending_callee_worker();	/* callee B */

	target = child_wait_for_service(COLOCATION_PENDING_CALLEE_SERVICE);

	my_pid = getpid();

	buf = 0;
	if (cocall(target, &buf, sizeof(buf), &buf, sizeof(buf)) < 0)
		err(EX_OSERR, "cocall");

	switch ((int)buf) {
	case CO_INCUMBENT:	/* A */
		release_then_hold_thread(NULL);
	case CO_PASS:		/* C, after B's check passed */
		wait_then_check_pid(NULL, my_pid);
	case CO_FAIL:		/* C, after B's check failed */
		exit(EX_SOFTWARE);
	default:
		errx(EX_SOFTWARE, "unexpected verdict %d", (int)buf);
	}
}

/*
 *	A>B
 *	B@
 *	A<B	=> {TB->A}
 *	C>B	=> {TB->A, TC->B, (C)}
 *	B@	|= {TB->B}
 *	C<B
 *	C@	|= {TC->C}
 *
 * Property under test: the callee's own syscall while serving the newcomer
 * must unborrow B back onto its home thread TB and run in B's process context,
 * which requires evicting the incumbent hosted on TB.  The newcomer's syscall
 * after the reply must then run as C.
 */
CHERIBSDTEST(colocation_pending_callee_unborrow,
    "Check that, with a first caller hosted on the callee's thread, the "
    "callee's syscall while it serves a second caller runs as the callee, "
    "and the second caller's next syscall runs as the second caller "
    "(multi-client cocall)",
    .ct_child_func = colocation_pending_callee_dispatch,
    .ct_check_skip = skip_known_panic,
    .ct_xfail_reason =
	"Multi-client cocall is not yet supported: a second caller's cocall "
	"clears the first caller's borrow record, and nothing evicts the first "
	"caller from the callee's home thread")
{
	/*
	 * XXX: the check fails with a wrong pid, and the failing test leaves
	 * the incumbent hosted on TB.  A later SIGKILL to the incumbent hits
	 * a separate bug that hangs or panics the kernel, so the test is
	 * skipped as a panic.
	 */
	colocation_coexec_run(3, "callee saw the wrong pid");
}

#define	COLOCATION_PENDING_INCUMBENT_SERVICE	"colocation_pending_incumbent"

static void __dead2
pending_incumbent_worker(void)
{
	static volatile int barrier = 1;

	struct caller_message msg;
	int cocall_count;

	cocall_count = 0;
	for (;;) {
		msg.barrier = &barrier;
		msg.role = (cocall_count == 1) ? CO_INCUMBENT : CO_NEWCOMER;

		if (coaccept(NULL, &msg, sizeof(msg), &msg, sizeof(msg)) < 0)
			err(EX_OSERR, "coaccept");

		if (cocall_count == 0) {
			/*
			 * Any syscall would do.  It moves B's code back to
			 * its own thread TB, where B then replies.
			 */
			(void)getpid();
			cocall_count++;
		} else {
			/* Release A without a syscall, which would move B. */
			barrier = 0;

			/* Never reply, so that C's cocall stays pending. */
			for (;;)
				;
		}
	}
}

static void
colocation_pending_incumbent_dispatch(void)
{
	struct caller_message msg;
	void *target;
	pid_t my_pid;

	if (coregister_wins(COLOCATION_PENDING_INCUMBENT_SERVICE))
		pending_incumbent_worker();	/* callee B */

	target = child_wait_for_service(COLOCATION_PENDING_INCUMBENT_SERVICE);

	my_pid = getpid();

	msg.barrier = NULL;
	msg.role = 0;
	if (cocall(target, &msg, sizeof(msg), &msg, sizeof(msg)) < 0)
		err(EX_OSERR, "cocall");

	/*
	 * B never replies to C, so only A gets here.  A reports the verdict:
	 * its syscall must run as A.
	 */
	if (msg.role != CO_INCUMBENT)
		errx(EX_SOFTWARE, "newcomer's cocall returned");

	wait_then_check_pid(msg.barrier, my_pid);
}

/*
 *	A>B
 *	B@
 *	A<B	=> {TB->A}
 *	C>B	=> {TB->A, TC->B, (C)}
 *	A@	|= {TA->A}
 *
 * Property under test: a newcomer whose cocall is still pending must not
 * prevent the incumbent's syscall from unborrowing back to its own thread.
 */
CHERIBSDTEST(colocation_pending_incumbent_unborrow,
    "Check that, while a second caller's cocall to the same callee is still "
    "pending, the first caller's next syscall runs on its own thread as "
    "itself (multi-client cocall)",
    .ct_child_func = colocation_pending_incumbent_dispatch,
    .ct_check_skip = skip_known_panic,
    .ct_xfail_reason =
	"Multi-client cocall is not yet supported: a second caller's cocall "
	"clears the first caller's borrow record")
{
	/*
	 * XXX: on SMP, both callers' cocalls can enter B at once, because the
	 * switcher's lock is a plain load and store.  The test then hangs
	 * until cheribsdtest times it out, and a later SIGKILL to its
	 * remaining processes panics the kernel.
	 */
	colocation_coexec_run(3, "incumbent saw the wrong pid");
}

#define	COLOCATION_NESTED_LEAF_SERVICE		"colocation_nested_leaf"
#define	COLOCATION_NESTED_MIDDLE_SERVICE	"colocation_nested_middle"

static void __dead2
nested_leaf_worker(void)
{
	intcap_t buf;
	pid_t my_pid, observed_pid;

	my_pid = getpid();

	buf = CO_FAIL;
	for (;;) {
		if (coaccept(NULL, &buf, sizeof(buf), &buf, sizeof(buf)) < 0)
			err(EX_OSERR, "coaccept");

		observed_pid = getpid();
		buf = (observed_pid == my_pid) ? CO_PASS : CO_FAIL;
	}
}

static void __dead2
nested_middle_worker(void)
{
	intcap_t buf, leaf_buf;
	void *cocall_code;
	void *cocall_data;
	void *leaf;
	pid_t my_pid, observed_pid;

	leaf = child_wait_for_service(COLOCATION_NESTED_LEAF_SERVICE);

	/*
	 * cosetup() keeps the sealed pair in variables private to libsys, so
	 * get a copy with the raw syscall.
	 */
	if (_cosetup(COSETUP_COCALL, &cocall_code, &cocall_data) != 0)
		err(EX_OSERR, "_cosetup");

	my_pid = getpid();

	buf = CO_FAIL;
	for (;;) {
		if (coaccept(NULL, &buf, sizeof(buf), &buf, sizeof(buf)) < 0)
			err(EX_OSERR, "coaccept");

		leaf_buf = 0;

		/*
		 * The switcher returns EAGAIN until D waits in its first
		 * coaccept.  cocall() retries after __usleep(), whose syscall
		 * would move B's code back to TB and turn the chain into two
		 * separate round trips, so retry here without a syscall.
		 */
		while (_cocall(cocall_code, cocall_data, leaf, &leaf_buf,
		    sizeof(leaf_buf), &leaf_buf, sizeof(leaf_buf)) < 0) {
			if (errno != EAGAIN)
				err(EX_OSERR, "_cocall");
		}

		observed_pid = getpid();
		buf = (observed_pid == my_pid && (int)leaf_buf == CO_PASS) ?
		    CO_PASS : CO_FAIL;
	}
}

static void
colocation_nested_chain_dispatch(void)
{
	void *target;
	intcap_t buf;
	pid_t my_pid, observed_pid;
	int error;

	if (cosetup(COSETUP_COACCEPT) != 0)
		err(EX_OSERR, "cosetup_coaccept");

	/* Leaf callee D wins this; middle B and outer A fall through. */
	error = coregister(COLOCATION_NESTED_LEAF_SERVICE, NULL);
	if (error == 0)
		nested_leaf_worker();		/* callee D */
	if (errno != EEXIST)
		err(EX_OSERR, "coregister leaf");

	error = coregister(COLOCATION_NESTED_MIDDLE_SERVICE, NULL);
	if (error == 0)
		nested_middle_worker();		/* callee B, caller of D */
	if (errno != EEXIST)
		err(EX_OSERR, "coregister middle");

	/* Both services taken: we are the outermost caller A. */
	target = child_wait_for_service(COLOCATION_NESTED_MIDDLE_SERVICE);

	my_pid = getpid();

	buf = 0;
	if (cocall(target, &buf, sizeof(buf), &buf, sizeof(buf)) < 0)
		err(EX_OSERR, "cocall");

	observed_pid = getpid();
	exit((observed_pid == my_pid && (int)buf == CO_PASS) ? 0 : EX_SOFTWARE);
}

/*
 * Three colocated processes with kernel threads TA, TB, and TD: D is the
 * leaf callee, B the middle (callee of A, caller of D), and A the outermost
 * caller.  B's cocall to D returns before B replies to A (B<D before A<B),
 * so each callee serves one caller at a time.
 *
 *	A>B	=> {TA->B, (A)}
 *	B>D	=> {TA->D, (A), (B)}
 *	D@	|= {TD->D}
 *	B<D	=> {TD->B, (A)}
 *	B@	|= {TB->B}
 *	A<B	=> {TB->A}
 *	A@	|= {TA->A}
 *
 * Property under test: D@, B@, and A@ each move their code back to its own
 * thread, so that the syscall runs as that process.
 */
CHERIBSDTEST(colocation_nested_chain_unborrow,
    "Check that a strictly nested cocall chain (A calls B, B calls D) "
    "preserves each process's identity across the nested borrows and returns",
    .ct_child_func = colocation_nested_chain_dispatch)
{
	colocation_coexec_run(3, "nested chain saw the wrong pid");
}

#endif /* !CHERIBSD_C18N_TESTS */

#if defined(__aarch64__)
/*
 * Tests that the cocall switcher gives the caller and the callee each
 * their own register values.
 */

#define	COLOCATION_REGISTER_TEST_SERVICE	"colocation_register_test"

static void
colocation_echo_worker(void)
{
	intcap_t buf = 0;

	if (cosetup(COSETUP_COACCEPT) != 0)
		err(EX_OSERR, "cosetup");

	if (coregister(COLOCATION_REGISTER_TEST_SERVICE, NULL) != 0)
		err(EX_OSERR, "coregister");

	for (;;) {
		if (coaccept(NULL, &buf, sizeof(buf), &buf,
		    sizeof(buf)) < 0)
			err(EX_OSERR, "coaccept");
	}
}

static void
check_same_capability(const char *name, void *want, void *got,
    const char *across)
{
	if (__builtin_cheri_equal_exact(got, want))
		return;

	cheribsdtest_failure_errx("%s changed across %s: got %#p, want %#p",
	    name, across, got, want);
}

/*
 * Excluded under c18n, where a bug causes a cocall to fault.
 */
#ifndef CHERIBSD_C18N_TESTS

#define	FP_MARKER_FIRST_REG	8	/* q8 */
#define	FP_MARKER_COUNT		8	/* q8-q15 */

/*
 * The value of one of q8-q15.  AAPCS requires a callee to preserve only
 * the low half (d8-d15), but the switcher saves all 128 bits.  The markers have
 * different low and high halves, so the check fails if the switcher
 * saves only d8-d15.  The worker sends these structures through
 * coaccept(), whose buffers must be aligned to a capability.
 */
struct fp_q_value {
	uint64_t	low;
	uint64_t	high;
} __aligned(16);

/* Defined in arm64/cheribsdtest_colocation_asm.S. */
ssize_t	cocall_with_fp_markers(void *target,
	    const struct fp_q_value *markers, struct fp_q_value *values);

ssize_t	cocall_with_gp_markers(void *target,
	    void * const *markers, void **values);

ssize_t	coaccept_with_fp_markers(void *cookiep,
	    const struct fp_q_value *markers, struct fp_q_value *values);

ssize_t	coaccept_with_gp_markers(void *cookiep,
	    void * const *markers, void **values);

static void
build_fp_markers(struct fp_q_value markers[FP_MARKER_COUNT])
{
	int i;

	for (i = 0; i < FP_MARKER_COUNT; i++) {
		markers[i].low = 0x1000000000000000ULL + i;
		markers[i].high = 0x2000000000000000ULL + i;
	}
}

#define	GP_MARKER_FIRST_REG	19	/* c19 */
#define	GP_MARKER_COUNT		10	/* c19-c28 */

/*
 * Fill markers[] with distinct capabilities that point into marker_bytes[],
 * which must hold GP_MARKER_COUNT bytes.  The markers are tagged, so
 * the check fails if the switcher changes a tag, bounds, or
 * permissions, not only an address.
 */
static void
build_gp_markers(void *markers[GP_MARKER_COUNT], char *marker_bytes)
{
	int i;

	for (i = 0; i < GP_MARKER_COUNT; i++)
		markers[i] = &marker_bytes[i];
}

static void
check_fp_markers(const struct fp_q_value want[FP_MARKER_COUNT],
    const struct fp_q_value got[FP_MARKER_COUNT], const char *across)
{
	int i;

	for (i = 0; i < FP_MARKER_COUNT; i++) {
		if (got[i].low == want[i].low && got[i].high == want[i].high)
			continue;

		cheribsdtest_failure_errx("q%d changed across %s: got "
		    "%#lx:%016lx, want %#lx:%016lx", FP_MARKER_FIRST_REG + i,
		    across, got[i].high, got[i].low, want[i].high,
		    want[i].low);
	}
}

static void
check_scalar_marker(const char *name, unsigned long want,
    unsigned long got, const char *across)
{
	if (got == want)
		return;

	cheribsdtest_failure_errx("%s changed across %s: got %#lx, want %#lx",
	    name, across, got, want);
}

/* Sent through coaccept(), whose buffers must be aligned to a capability. */
struct fp_status_control {
	unsigned long	fpcr;
	unsigned long	fpsr;
} __aligned(16);

/*
 * Both markers are non-zero, so the check fails if the switcher zeroes
 * the registers.  The FPCR marker rounds towards plus infinity, and the
 * FPSR marker has the invalid-operation and inexact flags set.  A
 * floating-point instruction between writing the markers and reading
 * the registers back could set more FPSR flags, so the tests run none.
 */
static const struct fp_status_control fp_status_control_markers = {
	.fpcr = 0x00400000,
	.fpsr = 0x11,
};

static void
write_fp_status_control(const struct fp_status_control *fpsc)
{
	__asm__ __volatile__ (
	    "msr fpcr, %0\n\t"
	    "msr fpsr, %1"
	    : : "r" (fpsc->fpcr), "r" (fpsc->fpsr));
}

static void
read_fp_status_control(struct fp_status_control *fpsc)
{
	__asm__ __volatile__ (
	    "mrs %0, fpcr\n\t"
	    "mrs %1, fpsr"
	    : "=r" (fpsc->fpcr), "=r" (fpsc->fpsr));
}

/*
 * A switcher that strips tags passes the check unless the markers are
 * tagged.
 */
static void
check_gp_markers(void * const want[GP_MARKER_COUNT],
    void * const got[GP_MARKER_COUNT], const char *across)
{
	int i;

	for (i = 0; i < GP_MARKER_COUNT; i++) {
		if (!cheri_gettag(want[i]))
			cheribsdtest_failure_errx("marker for c%d is untagged",
			    GP_MARKER_FIRST_REG + i);

		if (__builtin_cheri_equal_exact(got[i], want[i]))
			continue;

		cheribsdtest_failure_errx("c%d changed across %s: got %#p, "
		    "want %#p", GP_MARKER_FIRST_REG + i, across, got[i],
		    want[i]);
	}
}

/*
 * The worker's reply: the markers and the values of c19-c28 after the
 * coaccept.  A coexec child can report only through its exit status, so the
 * worker sends both to the test, which does the check and names any register
 * that changed.  The test cannot build the markers itself, because they point
 * into the worker's stack.
 */
struct colocation_gp_cap_response {
	void	*markers[GP_MARKER_COUNT];
	void	*values[GP_MARKER_COUNT];
};

/*
 * The registers are set and read in assembly, so that the compiler cannot
 * save and restore them around the coaccept.  Unlike the c19-c28 worker,
 * this one sends back only the values it read: the markers are fixed
 * numbers, so the test builds its own copy.
 */
static void
colocation_callee_saved_fp_worker(void)
{
	intcap_t recv_buf = 0;
	struct fp_q_value markers[FP_MARKER_COUNT];
	struct fp_q_value values[FP_MARKER_COUNT];

	if (cosetup(COSETUP_COACCEPT) != 0)
		err(EX_OSERR, "cosetup");

	if (coregister(COLOCATION_REGISTER_TEST_SERVICE, NULL) != 0)
		err(EX_OSERR, "coregister");

	build_fp_markers(markers);

	if (coaccept_with_fp_markers(NULL, markers, values) < 0)
		err(EX_OSERR, "coaccept");

	if (coaccept(NULL, values, sizeof(values), &recv_buf,
	    sizeof(recv_buf)) < 0)
		err(EX_OSERR, "coaccept");

	errx(EX_SOFTWARE, "second coaccept returned");
}

/*
 * The registers are set and read in assembly, so that the compiler cannot
 * save and restore them around the coaccept.
 */
static void
colocation_callee_saved_gp_worker(void)
{
	intcap_t recv_buf = 0;
	struct colocation_gp_cap_response response;
	char marker_bytes[GP_MARKER_COUNT];

	if (cosetup(COSETUP_COACCEPT) != 0)
		err(EX_OSERR, "cosetup");

	if (coregister(COLOCATION_REGISTER_TEST_SERVICE, NULL) != 0)
		err(EX_OSERR, "coregister");

	build_gp_markers(response.markers, marker_bytes);

	if (coaccept_with_gp_markers(NULL, response.markers,
	    response.values) < 0)
		err(EX_OSERR, "coaccept");

	if (coaccept(NULL, &response, sizeof(response), &recv_buf,
	    sizeof(recv_buf)) < 0)
		err(EX_OSERR, "coaccept");

	errx(EX_SOFTWARE, "second coaccept returned");
}

static void
colocation_fp_status_control_worker(void)
{
	intcap_t recv_buf = 0;
	struct fp_status_control values;

	if (cosetup(COSETUP_COACCEPT) != 0)
		err(EX_OSERR, "cosetup");

	if (coregister(COLOCATION_REGISTER_TEST_SERVICE, NULL) != 0)
		err(EX_OSERR, "coregister");

	write_fp_status_control(&fp_status_control_markers);

	if (coaccept(NULL, &recv_buf, sizeof(recv_buf), &recv_buf,
	    sizeof(recv_buf)) < 0)
		err(EX_OSERR, "coaccept");

	read_fp_status_control(&values);

	if (coaccept(NULL, &values, sizeof(values), &recv_buf,
	    sizeof(recv_buf)) < 0)
		err(EX_OSERR, "coaccept");

	errx(EX_SOFTWARE, "second coaccept returned");
}

/*
 * The libc cocall() function can save and restore some of q8-q15
 * itself.  For those registers, the test passes whatever the switcher
 * does.
 */
CHERIBSDTEST(colocation_callee_saved_fp_via_cocall,
    "Check that a caller's q8-q15 keep their values across cocall()",
    .ct_child_func = colocation_echo_worker,
    .ct_xfail_reason =
	"The cocall switcher restores q8-q15 from the wrong slots")
{
	void *target;
	struct fp_q_value markers[FP_MARKER_COUNT];
	struct fp_q_value values[FP_MARKER_COUNT];
	pid_t pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGISTER_TEST_SERVICE,
		    pid);

		build_fp_markers(markers);

		if (cocall_with_fp_markers(target, markers, values) < 0)
			cheribsdtest_failure_err("cocall");

		check_fp_markers(markers, values, "cocall");

		cheribsdtest_success();
	}
}

/*
 * The libc cocall() function can save and restore some of c19-c28
 * itself.  For those registers, the test passes whatever the switcher
 * does.
 */
CHERIBSDTEST(colocation_callee_saved_gp_via_cocall,
    "Check that a caller's c19-c28 keep their values across cocall()",
    .ct_child_func = colocation_echo_worker)
{
	void *target;
	void *markers[GP_MARKER_COUNT];
	void *values[GP_MARKER_COUNT];
	char marker_bytes[GP_MARKER_COUNT];
	pid_t pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGISTER_TEST_SERVICE,
		    pid);

		build_gp_markers(markers, marker_bytes);

		if (cocall_with_gp_markers(target, markers, values) < 0)
			cheribsdtest_failure_err("cocall");

		check_gp_markers(markers, values, "cocall");

		cheribsdtest_success();
	}
}

CHERIBSDTEST(colocation_fp_status_control_via_cocall,
    "Check that a caller's FPCR and FPSR keep their values across cocall()",
    .ct_child_func = colocation_echo_worker)
{
	void *target;
	intcap_t buf = 0;
	struct fp_status_control values;
	pid_t pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGISTER_TEST_SERVICE,
		    pid);

		write_fp_status_control(&fp_status_control_markers);
		cocall_or_fail(target, &buf, sizeof(buf), &buf, sizeof(buf));
		read_fp_status_control(&values);

		check_scalar_marker("FPCR", fp_status_control_markers.fpcr,
		    values.fpcr, "cocall");
		check_scalar_marker("FPSR", fp_status_control_markers.fpsr,
		    values.fpsr, "cocall");

		cheribsdtest_success();
	}
}

/*
 * The libc coaccept() function can save and restore some of q8-q15
 * itself.  For those registers, the test passes whatever the switcher
 * does.
 */
CHERIBSDTEST(colocation_callee_saved_fp_via_coaccept,
    "Check that a callee's q8-q15 keep their values across coaccept()",
    .ct_child_func = colocation_callee_saved_fp_worker,
    .ct_xfail_reason =
	"The cocall switcher restores q8-q15 from the wrong slots")
{
	void *target;
	struct fp_q_value markers[FP_MARKER_COUNT];
	struct fp_q_value values[FP_MARKER_COUNT];
	intcap_t send_buf = 0;
	pid_t pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGISTER_TEST_SERVICE,
		    pid);

		cocall_or_fail(target, &send_buf, sizeof(send_buf), values,
		    sizeof(values));

		build_fp_markers(markers);
		check_fp_markers(markers, values, "coaccept");

		cheribsdtest_success();
	}
}

CHERIBSDTEST(colocation_callee_saved_gp_via_coaccept,
    "Check that a callee's c19-c28 keep their values across coaccept()",
    .ct_child_func = colocation_callee_saved_gp_worker)
{
	void *target;
	struct colocation_gp_cap_response response;
	intcap_t send_buf = 0;
	pid_t pid;

	/*
	 * Start the reply with untagged markers, which fail the check, so
	 * that only a correct reply from the worker passes.
	 */
	memset(&response, 0, sizeof(response));

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGISTER_TEST_SERVICE,
		    pid);

		cocall_or_fail(target, &send_buf, sizeof(send_buf),
		    &response, sizeof(response));

		check_gp_markers(response.markers, response.values, "coaccept");

		cheribsdtest_success();
	}
}

CHERIBSDTEST(colocation_fp_status_control_via_coaccept,
    "Check that a callee's FPCR and FPSR keep their values across coaccept()",
    .ct_child_func = colocation_fp_status_control_worker)
{
	void *target;
	intcap_t send_buf = 0;
	struct fp_status_control values;
	pid_t pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGISTER_TEST_SERVICE,
		    pid);

		cocall_or_fail(target, &send_buf, sizeof(send_buf), &values,
		    sizeof(values));

		check_scalar_marker("FPCR", fp_status_control_markers.fpcr,
		    values.fpcr, "coaccept");
		check_scalar_marker("FPSR", fp_status_control_markers.fpsr,
		    values.fpsr, "coaccept");

		cheribsdtest_success();
	}
}

#endif /* !CHERIBSD_C18N_TESTS */

static void *
read_ctpidr_el0(void)
{
	void *v;

	__asm__ __volatile__ ("mrs %0, ctpidr_el0" : "=C" (v));
	return (v);
}

/*
 * The reply from register_across_coaccept_worker(): a register's value
 * before the worker entered coaccept() and after coaccept() returned.
 */
struct colocation_register_response {
	void	*before;
	void	*after;
};

/* Worker for check_register_across_coaccept(). */
static void
register_across_coaccept_worker(void *(*read_register)(void))
{
	intcap_t recv_buf = 0;
	struct colocation_register_response response;

	if (cosetup(COSETUP_COACCEPT) != 0)
		err(EX_OSERR, "cosetup");

	if (coregister(COLOCATION_REGISTER_TEST_SERVICE, NULL) != 0)
		err(EX_OSERR, "coregister");

	response.before = read_register();

	if (coaccept(NULL, &recv_buf, sizeof(recv_buf), &recv_buf,
	    sizeof(recv_buf)) < 0)
		err(EX_OSERR, "coaccept");

	response.after = read_register();

	if (coaccept(NULL, &response, sizeof(response), &recv_buf,
	    sizeof(recv_buf)) < 0)
		err(EX_OSERR, "coaccept");

	errx(EX_SOFTWARE, "second coaccept returned");
}

typedef void register_check_t(const char *name, void *want, void *got,
    const char *across);

static void
check_register_across_cocall(const char *name, void *(*read_register)(void),
    register_check_t *check)
{
	void *target;
	void *before;
	void *after;
	intcap_t buf = 0;
	pid_t pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGISTER_TEST_SERVICE,
		    pid);

		before = read_register();
		cocall_or_fail(target, &buf, sizeof(buf), &buf, sizeof(buf));
		after = read_register();

		check(name, before, after, "cocall");

		cheribsdtest_success();
	}
}

static void
check_register_across_coaccept(const char *name, register_check_t *check)
{
	void *target;
	struct colocation_register_response response;
	intcap_t send_buf = 0;
	pid_t pid;

	/*
	 * Start the reply with values that fail the check, so that only a
	 * correct reply from the worker passes.
	 */
	response.before = NULL;
	response.after = &response;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGISTER_TEST_SERVICE,
		    pid);

		cocall_or_fail(target, &send_buf, sizeof(send_buf),
		    &response, sizeof(response));

		check(name, response.before, response.after, "coaccept");

		cheribsdtest_success();
	}
}

/*
 * The CTPIDR_EL0 tests read the register before and after the call,
 * rather than loading a marker into it.  CTPIDR_EL0 is the TLS pointer,
 * and cocall() and coaccept() read thread-local variables, so a marker
 * would cause them to fault before the switcher ran.
 *
 * In c18n's purecap ABI, the TLS pointer is RCTPIDR_EL0.  The tests still
 * check it, because they run in Restricted mode, where reads of CTPIDR_EL0
 * return RCTPIDR_EL0.
 *
 * The cocall() test catches a switcher that restores the wrong value to
 * the caller.  The coaccept() test catches one that does not give the
 * callee its own value: the worker reads CTPIDR_EL0 before it waits and
 * again when coaccept() returns, and the two must match.
 */
static void
colocation_ctpidr_el0_worker(void)
{
	register_across_coaccept_worker(read_ctpidr_el0);
}

CHERIBSDTEST(colocation_ctpidr_el0_via_cocall,
    "Check that a caller's CTPIDR_EL0 keeps its value across cocall()",
    .ct_child_func = colocation_echo_worker,
    .ct_xfail_reason = XFAIL_C18N_COCALL_FAULT)
{
	check_register_across_cocall("CTPIDR_EL0", read_ctpidr_el0,
	    check_same_capability);
}

CHERIBSDTEST(colocation_ctpidr_el0_via_coaccept,
    "Check that a callee's CTPIDR_EL0 keeps its value across coaccept()",
    .ct_child_func = colocation_ctpidr_el0_worker,
    .ct_xfail_reason = XFAIL_C18N_COCALL_FAULT)
{
	check_register_across_coaccept("CTPIDR_EL0", check_same_capability);
}

static void *
read_csp(void)
{
	void *v;

	__asm__ __volatile__ ("mov %0, csp" : "=C" (v));
	return (v);
}

/*
 * The stack pointer tests read the register before and after the call,
 * rather than loading a marker into it, because the code in between
 * needs a working stack.  In c18n's purecap ABI, they run in Restricted
 * mode, where the stack pointer is RCSP_EL0.
 *
 * The cocall() test catches a switcher that restores the wrong stack
 * pointer to the caller.  The coaccept() test catches one that does not
 * switch to the callee's stack.
 */
static void
colocation_csp_worker(void)
{
	register_across_coaccept_worker(read_csp);
}

CHERIBSDTEST(colocation_csp_via_cocall,
    "Check that a caller's stack pointer keeps its value across cocall()",
    .ct_child_func = colocation_echo_worker,
    .ct_xfail_reason = XFAIL_C18N_COCALL_FAULT)
{
	check_register_across_cocall("stack pointer", read_csp,
	    check_same_capability);
}

CHERIBSDTEST(colocation_csp_via_coaccept,
    "Check that a callee's stack pointer keeps its value across coaccept()",
    .ct_child_func = colocation_csp_worker,
    .ct_xfail_reason = XFAIL_C18N_COCALL_FAULT)
{
	check_register_across_coaccept("stack pointer", check_same_capability);
}

/*
 * Under c18n (library compartmentalisation), rtld splits a program into
 * compartments, mostly one per library, each with its own stack.  On each
 * call into a compartment, rtld finds that compartment's stack in the
 * calling thread's stack table.  In the purecap ABI, rtld keeps a pointer
 * to the table in the Executive-mode CTPIDR_EL0, which compartment code
 * cannot read.
 *
 * libcheribsdtest_dynamic is a compartment of its own, so its stack shows
 * which table the thread holds.  cheribsdtest's own stack would not: rtld
 * reads the table on a call into a compartment but not on a return to one,
 * and no call enters cheribsdtest's compartment during a test.
 *
 * check_register_across_cocall() and register_across_coaccept_worker() call
 * this function through a pointer.  By default, a call through a pointer
 * stays in the caller's compartment, so this function calls the library by
 * name.
 */
static void *
read_library_csp(void)
{
	return (cheribsdtest_dynamic_get_csp());
}

/*
 * The library's first call runs on a stack capability with the SW_VMEM
 * permission, and rtld removes that permission for later calls, so this
 * compares bounds rather than whole capabilities.
 */
static void
check_same_stack(const char *name, void *want, void *got, const char *across)
{
	if (cheri_gettag(got) && cheri_gettag(want) &&
	    cheri_getbase(got) == cheri_getbase(want) &&
	    cheri_getlen(got) == cheri_getlen(want))
		return;

	cheribsdtest_failure_errx("%s changed across %s: got %#p, want %#p",
	    name, across, got, want);
}

/*
 * The stack table tests read the library's stack before and after cocall()
 * or coaccept(), and check that it is the same.  If the thread holds
 * another process's table after cocall() or coaccept(), rtld gives the
 * library that process's stack, or a new one if that process has none.
 * Without c18n, the library runs on the caller's stack, and the tests
 * check only what the stack pointer tests check.
 *
 * The cocall() test catches a switcher that does not restore the caller's
 * stack table.  The coaccept() test catches one that does not give the
 * callee its own.
 */
static void
colocation_stack_table_worker(void)
{
	register_across_coaccept_worker(read_library_csp);
}

CHERIBSDTEST(colocation_stack_table_via_cocall,
    "Check that a caller keeps its own c18n stack table across cocall()",
    .ct_child_func = colocation_echo_worker,
    .ct_xfail_reason = XFAIL_C18N_COCALL_FAULT)
{
	check_register_across_cocall("library stack", read_library_csp,
	    check_same_stack);
}

CHERIBSDTEST(colocation_stack_table_via_coaccept,
    "Check that a callee keeps its own c18n stack table across coaccept()",
    .ct_child_func = colocation_stack_table_worker,
    .ct_xfail_reason = XFAIL_C18N_COCALL_FAULT)
{
	check_register_across_coaccept("library stack", check_same_stack);
}

/*
 * Excluded under c18n, where a bug causes a cocall to fault.
 */
#ifndef CHERIBSD_C18N_TESTS

/*
 * Tests that enter the switcher with no C code between loading the
 * markers and reading the registers back.  A libc wrapper that keeps a
 * register in its own frame hides a switcher bug in that register.
 */

/*
 * The registers the direct tests check.  The stack pointer and the link
 * register are left out because the helper needs them for itself.
 */
struct switcher_regset {
	void			*gp[GP_MARKER_COUNT];
	struct fp_q_value	fp[FP_MARKER_COUNT];
	uint64_t		fpcr;
	uint64_t		fpsr;
	void			*ctpidr_el0;
} __aligned(16);

_Static_assert(__offsetof(struct switcher_regset, gp) == REGSET_GP_OFF,
    "switcher_regset.gp offset must match REGSET_GP_OFF");

_Static_assert(__offsetof(struct switcher_regset, fp) == REGSET_FP_OFF,
    "switcher_regset.fp offset must match REGSET_FP_OFF");

_Static_assert(__offsetof(struct switcher_regset, fpcr) == REGSET_FPCR_OFF,
    "switcher_regset.fpcr offset must match REGSET_FPCR_OFF");

_Static_assert(__offsetof(struct switcher_regset, fpsr) == REGSET_FPSR_OFF,
    "switcher_regset.fpsr offset must match REGSET_FPSR_OFF");

_Static_assert(__offsetof(struct switcher_regset, ctpidr_el0) ==
    REGSET_CTPIDR_OFF,
    "switcher_regset.ctpidr_el0 offset must match REGSET_CTPIDR_OFF");

/* Defined in arm64/cheribsdtest_colocation_asm.S. */
ssize_t	enter_switcher_with_markers(void *code, void *data,
	    void *target_or_cookiep, const struct switcher_regset *markers,
	    struct switcher_regset *values);

/* One byte for each GP marker and one for the CTPIDR_EL0 marker. */
#define	SWITCHER_MARKER_BYTE_COUNT	(GP_MARKER_COUNT + 1)

static void
build_switcher_regset_markers(struct switcher_regset *markers,
    char *marker_bytes)
{
	build_gp_markers(markers->gp, marker_bytes);
	build_fp_markers(markers->fp);
	markers->fpcr = fp_status_control_markers.fpcr;
	markers->fpsr = fp_status_control_markers.fpsr;

	/*
	 * The CTPIDR_EL0 marker points to a byte that no GP marker points to,
	 * so the check fails if the switcher restores CTPIDR_EL0 from one of
	 * c19-c28, or the reverse.
	 */
	markers->ctpidr_el0 = &marker_bytes[GP_MARKER_COUNT];
}

static void
check_switcher_regset(const struct switcher_regset *want,
    const struct switcher_regset *got, const char *across)
{
	check_gp_markers(want->gp, got->gp, across);
	check_fp_markers(want->fp, got->fp, across);
	check_scalar_marker("FPCR", want->fpcr, got->fpcr, across);
	check_scalar_marker("FPSR", want->fpsr, got->fpsr, across);
	check_same_capability("CTPIDR_EL0", want->ctpidr_el0, got->ctpidr_el0,
	    across);
}

CHERIBSDTEST(colocation_switcher_cocall_direct,
    "Check that the switcher keeps a caller's c19-c28, q8-q15, FPCR, FPSR "
    "and CTPIDR_EL0 across a cocall, with no C frame that could restore a "
    "lost value",
    .ct_child_func = colocation_echo_worker,
    .ct_xfail_reason =
	"The cocall switcher restores q8-q15 from the wrong slots")
{
	void *target;
	void *cocall_code;
	void *cocall_data;
	struct switcher_regset markers;
	struct switcher_regset values;
	char marker_bytes[SWITCHER_MARKER_BYTE_COUNT];
	ssize_t ret;
	pid_t pid;

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGISTER_TEST_SERVICE,
		    pid);

		/*
		 * cosetup() keeps the sealed pair in variables private to
		 * libsys, so get a copy with the raw syscall.
		 */
		if (_cosetup(COSETUP_COCALL, &cocall_code, &cocall_data) != 0)
			cheribsdtest_failure_err("_cosetup");

		build_switcher_regset_markers(&markers, marker_bytes);

		/*
		 * The switcher returns EAGAIN until the worker waits in its
		 * first coaccept.  Retry, as libc's cocall() does.
		 */
		for (;;) {
			ret = enter_switcher_with_markers(cocall_code,
			    cocall_data, target, &markers, &values);

			if (ret != -EAGAIN)
				break;

			usleep(1000);
		}

		if (ret < 0)
			cheribsdtest_failure_errc((int)-ret,
			    "enter_switcher_with_markers");

		check_switcher_regset(&markers, &values, "direct cocall");

		cheribsdtest_success();
	}
}

/*
 * The worker's reply: the markers and the values of the registers after the
 * coaccept.  A coexec child can report only through its exit status, so the
 * worker sends both to the test, which does the check and names any register
 * that changed.  The test cannot build the markers itself, because some of
 * them point into the worker's stack.
 */
struct colocation_switcher_response {
	struct switcher_regset	markers;
	struct switcher_regset	values;
};

static void
colocation_switcher_coaccept_direct_worker(void)
{
	intcap_t recv_buf = 0;
	struct colocation_switcher_response response;
	void *coaccept_code;
	void *coaccept_data;
	char marker_bytes[SWITCHER_MARKER_BYTE_COUNT];
	ssize_t ret;

	/*
	 * cosetup() keeps the sealed pair in variables private to libsys, so
	 * get a copy with the raw syscall.
	 */
	if (_cosetup(COSETUP_COACCEPT, &coaccept_code, &coaccept_data) != 0)
		err(EX_OSERR, "_cosetup");

	if (coregister(COLOCATION_REGISTER_TEST_SERVICE, NULL) != 0)
		err(EX_OSERR, "coregister");

	build_switcher_regset_markers(&response.markers, marker_bytes);

	ret = enter_switcher_with_markers(coaccept_code, coaccept_data, NULL,
	    &response.markers, &response.values);

	if (ret < 0)
		errc(EX_OSERR, (int)-ret, "enter_switcher_with_markers");

	if (_coaccept(coaccept_code, coaccept_data, NULL, &response,
	    sizeof(response), &recv_buf, sizeof(recv_buf)) < 0)
		err(EX_OSERR, "_coaccept");

	errx(EX_SOFTWARE, "second coaccept returned");
}

CHERIBSDTEST(colocation_switcher_coaccept_direct,
    "Check that the switcher keeps a callee's c19-c28, q8-q15, FPCR, FPSR "
    "and CTPIDR_EL0 across a coaccept, with no C frame that could restore a "
    "lost value",
    .ct_child_func = colocation_switcher_coaccept_direct_worker,
    .ct_xfail_reason =
	"The cocall switcher restores q8-q15 from the wrong slots")
{
	void *target;
	intcap_t send_buf = 0;
	struct colocation_switcher_response response;
	pid_t pid;

	/*
	 * Start the reply with untagged markers, which fail the check, so
	 * that only a correct reply from the worker passes.
	 */
	memset(&response, 0, sizeof(response));

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_err("Fork failed");

	if (pid == 0) {
		cheribsdtest_coexec_child();
	} else {
		target = wait_for_service(COLOCATION_REGISTER_TEST_SERVICE,
		    pid);

		cocall_or_fail(target, &send_buf, sizeof(send_buf),
		    &response, sizeof(response));

		check_switcher_regset(&response.markers, &response.values,
		    "direct coaccept");

		cheribsdtest_success();
	}
}
#endif /* !CHERIBSD_C18N_TESTS */
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
