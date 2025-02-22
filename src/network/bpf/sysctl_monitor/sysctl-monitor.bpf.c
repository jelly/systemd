/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "sysctl-write-event.h"

struct {
        __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
        __type(key, u32);
        __type(value, u32);
        __uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
} written_sysctls SEC(".maps");

static bool my_streq(const char *s1, const char *s2, size_t l) {
        for (size_t i = 0; i < l; i++) {
                if (s1[i] != s2[i])
                        return false;
                if (s1[i] == 0)
                        return true;
        }
        return true;
}

struct str {
        char *s;
        size_t l;
};

static long cut_last(u64 i, struct str *str) {
        char *s;

        /* Sanity check for the preverifier */
        if (i >= str->l)
                return 1; /* exit from the loop */

        i = str->l - i - 1;
        s = str->s + i;

        if (*s == 0)
                return 0; /* continue */

        if (*s == '\n' || *s == '\r' || *s == ' ' || *s == '\t') {
                *s = 0;
                return 0; /* continue */
        }

        return 1; /* exit from the loop */
}

/* Cut off trailing whitespace and newlines */
static void chop(char *s, size_t l) {
        struct str str = { s, l };

        bpf_loop(l, cut_last, &str, 0);
}

SEC("cgroup/sysctl")
int sysctl_monitor(struct bpf_sysctl *ctx) {
        int r;

        /* Allow reads */
        if (!ctx->write)
                return 1;

        /* Declare the struct without contextually initializing it.
         * This avoid zero-filling the struct, which would be a waste of
         * resource and code size. Since we're sending an event even on failure,
         * truncate the strings to zero size, in case we don't populate them. */
        struct sysctl_write_event we;
        we.version = 1;
        we.errorcode = 0;
        we.path[0] = 0;
        we.comm[0] = 0;
        we.current[0] = 0;
        we.newvalue[0] = 0;

        /* Set the simple values first */
        we.pid = bpf_get_current_pid_tgid() >> 32;
        we.cgroup_id = bpf_get_current_cgroup_id();

        r = bpf_current_task_under_cgroup(&cgroup_map, 0);
        if (r < 0) {
                we.errorcode = r;
                goto send_event;
        }
        if (r == 1)
                return 1; /* Ignore events generated by us */

        /* Only monitor /proc/sys/net/ */
        r = bpf_sysctl_get_name(ctx, we.path, sizeof(we.path), 0);
        if (r < 0) {
                we.errorcode = r;
                goto send_event;
        }

        if (bpf_strncmp(we.path, 4, "net/") != 0)
                return 1;

        r = bpf_get_current_comm(we.comm, sizeof(we.comm));
        if (r < 0) {
                we.errorcode = r;
                goto send_event;
        }

        r = bpf_sysctl_get_current_value(ctx, we.current, sizeof(we.current));
        if (r < 0) {
                we.errorcode = r;
                goto send_event;
        }

        r = bpf_sysctl_get_new_value(ctx, we.newvalue, sizeof(we.newvalue));
        if (r < 0) {
                we.errorcode = r;
                goto send_event;
        }

        /* Both the kernel and userspace applications add a newline at the end,
         * remove it from both strings */
        chop(we.current, sizeof(we.current));
        chop(we.newvalue, sizeof(we.newvalue));

send_event:
        /* If new value differs or we encountered an error, send the event */
        if (r < 0 || !my_streq(we.current, we.newvalue, sizeof(we.current)))
                bpf_ringbuf_output(&written_sysctls, &we, sizeof(we), 0);

        return 1;
}

char _license[] SEC("license") = "GPL";
