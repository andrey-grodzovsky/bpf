// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 CrowdStrike */
#include <test_progs.h>
#include "bpf_util.h"

/*
 * Verify the per-record FTRACE_FL_PERMANENT mechanism for BPF trampolines:
 *
 *  1. A fentry link attached with BPF_F_TRACING_PERMANENT blocks
 *     kernel.ftrace_enabled=0 (write fails with EBUSY, value stays 1).
 *  2. A fentry link attached WITHOUT the flag does not block it.
 *  3. Attaching a permanent link while ftrace_enabled=0 is refused (EBUSY),
 *     while a non-permanent attach still succeeds.
 *  4. A shared function with one permanent + one non-permanent link keeps
 *     ftrace_enabled=0 refused until the permanent link is detached.
 */

#define FTRACE_ENABLED_PATH "/proc/sys/kernel/ftrace_enabled"

static int read_ftrace_enabled(int *val)
{
	char buf[16] = {};
	int fd, n;

	fd = open(FTRACE_ENABLED_PATH, O_RDONLY);
	if (fd < 0)
		return -errno;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -EIO;
	*val = atoi(buf);
	return 0;
}

/* Returns 0 on success, or -errno on write failure. */
static int write_ftrace_enabled(int val)
{
	char buf[4];
	int fd, n, len;

	fd = open(FTRACE_ENABLED_PATH, O_WRONLY);
	if (fd < 0)
		return -errno;
	len = snprintf(buf, sizeof(buf), "%d", val);
	n = write(fd, buf, len);
	if (n < 0) {
		int err = -errno;

		close(fd);
		return err;
	}
	close(fd);
	return 0;
}

static int load_fentry_prog(void)
{
	const struct bpf_insn prog[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	LIBBPF_OPTS(bpf_prog_load_opts, opts,
		.expected_attach_type = BPF_TRACE_FENTRY,
	);
	int btf_id;

	btf_id = libbpf_find_vmlinux_btf_id("bpf_fentry_test1",
					    opts.expected_attach_type);
	if (btf_id <= 0)
		return -1;
	opts.attach_btf_id = btf_id;

	return bpf_prog_load(BPF_PROG_TYPE_TRACING, NULL, "GPL",
			     prog, ARRAY_SIZE(prog), &opts);
}

static int attach_fentry(int prog_fd, bool permanent)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts);

	if (permanent)
		opts.flags = BPF_F_TRACING_PERMANENT;
	return bpf_link_create(prog_fd, 0, BPF_TRACE_FENTRY, &opts);
}

void test_ftrace_permanent(void)
{
	int orig = 1, val, prog_fd, prog_fd2, link_fd, link_fd2, err;

	/* Save and always restore ftrace_enabled. */
	if (read_ftrace_enabled(&orig)) {
		test__skip();
		return;
	}

	prog_fd = load_fentry_prog();
	if (!ASSERT_GE(prog_fd, 0, "load_fentry_prog"))
		goto restore;

	/* Scenario 1: permanent attach blocks ftrace_enabled=0. */
	if (test__start_subtest("permanent_blocks_disable")) {
		link_fd = attach_fentry(prog_fd, true);
		if (link_fd < 0 && link_fd == -EOPNOTSUPP) {
			/* 32-bit kernel: feature unavailable. */
			test__skip();
		} else if (ASSERT_GE(link_fd, 0, "permanent_attach")) {
			err = write_ftrace_enabled(0);
			ASSERT_EQ(err, -EBUSY, "disable_refused");
			ASSERT_OK(read_ftrace_enabled(&val), "read_back");
			ASSERT_EQ(val, 1, "still_enabled");
			close(link_fd);
			/* Now disable must succeed, then restore. */
			ASSERT_OK(write_ftrace_enabled(0), "disable_after_detach");
			ASSERT_OK(write_ftrace_enabled(1), "reenable");
		}
	}

	/* Scenario 2: non-permanent attach does not block. */
	if (test__start_subtest("nonpermanent_allows_disable")) {
		link_fd = attach_fentry(prog_fd, false);
		if (ASSERT_GE(link_fd, 0, "nonpermanent_attach")) {
			ASSERT_OK(write_ftrace_enabled(0), "disable_allowed");
			ASSERT_OK(write_ftrace_enabled(1), "reenable");
			close(link_fd);
		}
	}

	/* Scenario 3: permanent attach refused while ftrace disabled. */
	if (test__start_subtest("attach_while_disabled_refused")) {
		if (ASSERT_OK(write_ftrace_enabled(0), "disable")) {
			link_fd = attach_fentry(prog_fd, true);
			ASSERT_LT(link_fd, 0, "permanent_attach_refused");
			if (link_fd >= 0)
				close(link_fd);
			/* Non-permanent attach still works while disabled. */
			link_fd = attach_fentry(prog_fd, false);
			if (ASSERT_GE(link_fd, 0, "nonpermanent_attach_ok"))
				close(link_fd);
			ASSERT_OK(write_ftrace_enabled(1), "reenable");
		}
	}

	/* Scenario 4: shared record - permanent + non-permanent. */
	if (test__start_subtest("shared_record_refcount")) {
		prog_fd2 = load_fentry_prog();
		if (ASSERT_GE(prog_fd2, 0, "load_fentry_prog2")) {
			link_fd = attach_fentry(prog_fd, true);
			link_fd2 = attach_fentry(prog_fd2, false);
			if (ASSERT_GE(link_fd, 0, "permanent_attach") &&
			    ASSERT_GE(link_fd2, 0, "nonpermanent_attach")) {
				/* Drop the non-permanent one; still refused. */
				close(link_fd2);
				err = write_ftrace_enabled(0);
				ASSERT_EQ(err, -EBUSY, "still_refused");
				ASSERT_OK(read_ftrace_enabled(&val), "read_back");
				ASSERT_EQ(val, 1, "still_enabled");
				/* Drop the permanent one; now allowed. */
				close(link_fd);
				ASSERT_OK(write_ftrace_enabled(0), "now_allowed");
				ASSERT_OK(write_ftrace_enabled(1), "reenable");
			} else {
				if (link_fd >= 0)
					close(link_fd);
				if (link_fd2 >= 0)
					close(link_fd2);
			}
			close(prog_fd2);
		}
	}

	close(prog_fd);
restore:
	write_ftrace_enabled(orig);
}
