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
#include <string.h>
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

/*
 * Excluded under c18n, where a bug causes a cocall to fault.
 */
#ifndef CHERIBSD_C18N_TESTS

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

/* Defined in arm64/cheribsdtest_colocation_asm.S. */
ssize_t	cocall_with_gp_markers(void *target,
	    void * const *markers, void **values);

ssize_t	coaccept_with_gp_markers(void *cookiep,
	    void * const *markers, void **values);

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
#endif /* defined(__aarch64__) */
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
