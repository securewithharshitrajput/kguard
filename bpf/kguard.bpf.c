// SPDX-License-Identifier: GPL-2.0
// kguard.bpf.c — kernel-side eBPF programs for the kguard endpoint monitor.
//
// These programs run inside the kernel, attached to tracepoints. They capture
// process launches/exits and TCP connections, do cheap in-kernel filtering,
// and push fixed-size `struct event` records to user space via a ring buffer.
//
// Compiled to BPF bytecode by clang (see Makefile) and loaded from Go using
// the cilium/ebpf library + bpf2go.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

// vmlinux.h does not provide userspace socket constants.
#ifndef AF_INET
#define AF_INET 2
#endif

// Ring buffer: the fast channel from kernel to user space. 256 KiB.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Scratch per-CPU buffer so we don't blow the 512-byte BPF stack with a big
// struct event. One element, indexed by CPU.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} scratch SEC(".maps");

static __always_inline struct event *new_event(__u8 kind)
{
    __u32 zero = 0;
    struct event *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->kind = kind;
    e->ts_ns = bpf_ktime_get_ns();

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (__u32)uid_gid;
    e->gid = uid_gid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return e;
}

static __always_inline void submit(struct event *e)
{
    bpf_ringbuf_output(&events, e, sizeof(*e), 0);
}

// --- Process launch -------------------------------------------------------
// tracepoint/sched/sched_process_exec fires on every successful execve.
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct event *e = new_event(EVENT_EXEC);
    if (!e)
        return 0;

    // The filename lives at ctx + data_loc offset (lower 16 bits).
    unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename),
                              (void *)ctx + fname_off);

    // Grab the start of argv from the current task's mm for context
    // (full argv parsing is done more cheaply in user space; this is a hint).
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    unsigned long arg_start = BPF_CORE_READ(task, mm, arg_start);
    unsigned long arg_end = BPF_CORE_READ(task, mm, arg_end);
    unsigned long len = arg_end - arg_start;
    if (len > sizeof(e->args) - 1)
        len = sizeof(e->args) - 1;
    if (len > 0)
        bpf_probe_read_user(&e->args, len, (void *)arg_start);

    submit(e);
    return 0;
}

// --- Process exit ---------------------------------------------------------
SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    // Only report the thread group leader exiting (the "process"), not every thread.
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if ((pid_tgid >> 32) != (__u32)pid_tgid)
        return 0;

    struct event *e = new_event(EVENT_EXIT);
    if (!e)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int code = BPF_CORE_READ(task, exit_code);
    e->exit_code = (code >> 8) & 0xff;

    submit(e);
    return 0;
}

// --- Outbound TCP connect -------------------------------------------------
// fentry on tcp_connect gives us the full sock before the handshake.
SEC("fentry/tcp_connect")
int BPF_PROG(handle_connect, struct sock *sk)
{
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET) // IPv4 only for now
        return 0;

    struct event *e = new_event(EVENT_CONNECT);
    if (!e)
        return 0;

    e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    submit(e);
    return 0;
}

// --- Inbound accepted connection ------------------------------------------
// fexit on inet_csk_accept: the return value is the newly accepted sock.
SEC("fexit/inet_csk_accept")
int BPF_PROG(handle_accept, struct sock *sk, int flags, int *err, bool kern,
             struct sock *ret)
{
    if (!ret)
        return 0;

    __u16 family = BPF_CORE_READ(ret, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    struct event *e = new_event(EVENT_ACCEPT);
    if (!e)
        return 0;

    e->saddr = BPF_CORE_READ(ret, __sk_common.skc_rcv_saddr);
    e->daddr = BPF_CORE_READ(ret, __sk_common.skc_daddr);
    e->sport = BPF_CORE_READ(ret, __sk_common.skc_num);
    e->dport = bpf_ntohs(BPF_CORE_READ(ret, __sk_common.skc_dport));

    submit(e);
    return 0;
}
