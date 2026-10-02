/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/btrfs.h>
#include <linux/magic.h>
#include <sys/ioctl.h>

#include "sd-json.h"
#include "sd-varlink.h"

#include "fd-util.h"
#include "fileio.h"
#include "hash-funcs.h"
#include "hexdecoct.h"
#include "json-util.h"
#include "log.h"
#include "metrics.h"
#include "report-btrfs.h"
#include "set.h"
#include "stdio-util.h"
#include "string-util.h"

static int btrfs_dev_stats_send(
                const MetricFamily *mf,
                sd_varlink *link,
                const char *object,
                uint64_t devid,
                const struct btrfs_ioctl_get_dev_stats *stats) {

        static const struct {
                const char *name;
                unsigned index;
        } stat_types[] = {
                { "write_io_errs",    BTRFS_DEV_STAT_WRITE_ERRS      },
                { "read_io_errs",     BTRFS_DEV_STAT_READ_ERRS       },
                { "flush_io_errs",    BTRFS_DEV_STAT_FLUSH_ERRS      },
                { "corruption_errs",  BTRFS_DEV_STAT_CORRUPTION_ERRS },
                { "generation_errs",  BTRFS_DEV_STAT_GENERATION_ERRS },
        };

        int r;

        assert(mf);
        assert(link);
        assert(object);
        assert(stats);

        FOREACH_ELEMENT(t, stat_types) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;

                char devid_str[DECIMAL_STR_MAX(uint64_t)];
                xsprintf(devid_str, "%" PRIu64, devid);

                r = sd_json_buildo(
                                &fields,
                                SD_JSON_BUILD_PAIR_STRING("type", t->name),
                                SD_JSON_BUILD_PAIR_STRING("devid", devid_str));
                if (r < 0)
                        return log_error_errno(r, "Failed to build metric fields: %m");

                r = metric_build_send_unsigned(mf, link, object, stats->values[t->index], fields);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int btrfs_mount_send(const MetricFamily *mf, sd_varlink *link, const char *path, int fd) {
        int r;

        assert(mf);
        assert(link);
        assert(path);
        assert(fd >= 0);

        struct btrfs_ioctl_fs_info_args fs_info = {};
        if (ioctl(fd, BTRFS_IOC_FS_INFO, &fs_info) < 0)
                return log_debug_errno(errno, "BTRFS_IOC_FS_INFO failed on '%s', skipping: %m", path);

        for (uint64_t devid = 1; devid <= fs_info.max_id; devid++) {
                struct btrfs_ioctl_get_dev_stats dev_stats = {
                        .devid = devid,
                        .nr_items = BTRFS_DEV_STAT_VALUES_MAX,
                        .flags = 0,
                };

                if (ioctl(fd, BTRFS_IOC_GET_DEV_STATS, &dev_stats) < 0) {
                        if (errno == ENODEV)
                                continue;
                        log_debug_errno(errno, "BTRFS_IOC_GET_DEV_STATS failed for devid %" PRIu64 " on '%s', skipping device: %m", devid, path);
                        continue;
                }

                r = btrfs_dev_stats_send(mf, link, path, devid, &dev_stats);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int btrfs_stats_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_set_free_ Set *seen_fsids = NULL;
        int r;

        assert(mf && mf->name);
        assert(link);

        r = fopen_unlocked("/proc/self/mountinfo", "re", &f);
        if (r < 0)
                return log_error_errno(r, "Failed to open /proc/self/mountinfo: %m");

        for (;;) {
                _cleanup_free_ char *line = NULL, *path = NULL, *fstype = NULL;
                char *dash, *type_start;
                int mnt_id, parent_id;
                unsigned major, minor;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read /proc/self/mountinfo: %m");
                if (r == 0)
                        break;

                /* mountinfo format:
                 * mnt_id parent_id major:minor root mount_point options ... - fstype source super_options */
                _cleanup_free_ char *root = NULL, *mount_point = NULL;
                if (sscanf(line, "%i %i %u:%u", &mnt_id, &parent_id, &major, &minor) != 4)
                        continue;

                dash = strstr(line, " - ");
                if (!dash)
                        continue;

                type_start = dash + 3;
                /* fstype is the first field after " - " */
                size_t type_len = strcspn(type_start, " ");
                fstype = strndup(type_start, type_len);
                if (!fstype)
                        return log_oom();

                if (!streq(fstype, "btrfs"))
                        continue;

                /* Extract mount point: it's the 5th field */
                const char *p = line;
                for (int i = 0; i < 4; i++) {
                        p += strcspn(p, " ");
                        p += strspn(p, " ");
                }
                size_t path_len = strcspn(p, " ");
                path = strndup(p, path_len);
                if (!path)
                        return log_oom();

                _cleanup_close_ int fd = open(path, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY|O_DIRECTORY);
                if (fd < 0) {
                        log_debug_errno(errno, "Failed to open btrfs mount '%s', skipping: %m", path);
                        continue;
                }

                /* Deduplicate by fsid so multi-mount btrfs filesystems are reported only once */
                struct btrfs_ioctl_fs_info_args fs_info = {};
                if (ioctl(fd, BTRFS_IOC_FS_INFO, &fs_info) < 0) {
                        log_debug_errno(errno, "BTRFS_IOC_FS_INFO failed on '%s', skipping: %m", path);
                        continue;
                }

                _cleanup_free_ char *fsid_hex = hexmem(fs_info.fsid, sizeof(fs_info.fsid));
                if (!fsid_hex)
                        return log_oom();

                if (set_contains(seen_fsids, fsid_hex)) {
                        log_debug("Btrfs filesystem on '%s' already reported, skipping.", path);
                        continue;
                }

                r = set_ensure_consume(&seen_fsids, &string_hash_ops_free, TAKE_PTR(fsid_hex));
                if (r < 0)
                        return log_oom();

                r = btrfs_mount_send(mf, link, path, fd);
                if (r < 0)
                        return r;
        }

        return 0;
}

static const MetricFamily btrfs_metric_family_table[] = {
        {
                "io.systemd.Btrfs.Stats",
                "Btrfs per-device I/O and integrity error counters "
                "(object=mount point, fields: type=error category, devid=btrfs device id)",
                METRIC_FAMILY_TYPE_GAUGE,
                .generate = btrfs_stats_generate,
        },
        {}
};

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(btrfs_metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(btrfs_metric_family_table, link, parameters, flags, userdata);
}
