#include "common.h"
#include "bpf_helpers.h"

#define FNAME_LEN 64
struct event_data_t
{
    u32 pid;
    u8 fname[FNAME_LEN];
    u8 comm[FNAME_LEN];
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

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

int strLen(const char *s)
{
    int i = 0, count = 0;
    while (s[i++] != '\0')
    {
        count += 1;
    }

    return count;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_open(struct openat_entry_args_t *args)
{
    struct event_data_t event_data = {};
    event_data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(event_data.fname,
                            sizeof(event_data.fname), args->filename);
    bpf_get_current_comm(event_data.comm, sizeof(event_data.comm));

    bpf_perf_event_output(args, &events,
                          BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

char _LICENSE[] SEC("license") = "GPL";