// SPDX-License-Identifier: GPL-2.0
// common.h — event structs shared between the eBPF (kernel) side and Go (user) side.
// The memory layout here MUST match the Go structs in internal/events/types.go.
#ifndef __KGUARD_COMMON_H
#define __KGUARD_COMMON_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN 256

// Event kinds. Keep in sync with internal/events/types.go.
enum event_kind {
    EVENT_EXEC    = 1,
    EVENT_EXIT    = 2,
    EVENT_CONNECT = 3,
    EVENT_ACCEPT  = 4,
    EVENT_FILE    = 5,
};

// One fixed-size record per event, sent through the ring buffer.
// A single struct (rather than one per kind) keeps the Go decoder simple.
struct event {
    __u8  kind;        // enum event_kind
    __u8  _pad[3];
    __u32 pid;         // process (thread group) id
    __u32 ppid;        // parent pid
    __u32 uid;         // real user id
    __u32 gid;         // real group id
    __u32 exit_code;   // EXIT only

    __u64 ts_ns;       // monotonic timestamp (ns)

    // networking (CONNECT / ACCEPT)
    __u32 saddr;       // source IPv4, network byte order
    __u32 daddr;       // dest IPv4, network byte order
    __u16 sport;       // host byte order
    __u16 dport;       // host byte order

    char comm[TASK_COMM_LEN];       // short process name
    char filename[MAX_FILENAME_LEN]; // exec path / opened file path
    char args[MAX_ARGS_LEN];         // first chunk of argv, NUL-separated
};

#endif // __KGUARD_COMMON_H
