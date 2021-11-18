#include "common.h"
#include "bpf_helpers.h"

#define TASK_COMM_LEN 16
#define FILENAME_LEN 64
struct event_data_t
{
    u32 uid;
    u32 pid;
    char fname[FILENAME_LEN];
    char comm[TASK_COMM_LEN];
};

// TODO ringbuf
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static int hasprefix(char *s, char *pres, int size)
{
    for (int i = 0; i < size; ++i)
        if (s[i] != pres[i])
            return 0;
    return 1;
}

// cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
struct openat_entry_args_t
{
    u64 _unused;      //8 bytes
    u64 __syscall_nr; //8 bytes
    u64 dfd;          //8 bytes

    const char *filename;
    u64 flags; //8 bytes
    u64 mode;  //8 bytes
};

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct openat_entry_args_t *args)
{
    struct event_data_t event_data = {};
    bpf_probe_read_user_str(event_data.fname,
                            sizeof(event_data.fname), args->filename);
    // filter “/proc/”
    char prestr[6] = "/proc/";
    if (!hasprefix(event_data.fname, prestr, sizeof(prestr)))
    {
        return 0;
    }

    event_data.uid = bpf_get_current_uid_gid() >> 32;
    event_data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(event_data.comm, sizeof(event_data.comm));
    bpf_perf_event_output(args, &events,
                          BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

char _LICENSE[] SEC("license") = "GPL";