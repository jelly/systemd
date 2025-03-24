/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>

#include "errno-list.h"
#include "macro.h"

int acquire_path(char **path);
int make_good(const char *prefix, const char *suffix, char **ret);
int make_bad(const char *prefix, uint64_t done, const char *suffix, char **ret);
int acquire_boot_count_path(
                char **ret_path,
                char **ret_prefix,
                uint64_t *ret_left,
                uint64_t *ret_done,
                char **ret_suffix);

typedef enum BlessBootStatus {
        BLESS_BOOT_STATUS_GOOD,
        BLESS_BOOT_STATUS_BAD,
        BLESS_BOOT_STATUS_INTERMEDIATE,
        BLESS_BOOT_STATUS_CLEAN,
        _BLESS_BOOT_STATUS_MAX,
        _BLESS_BOOT_STATUS_INVALID = -EINVAL,
        _BLESS_BOOT_STATUS_ERRNO_MAX = -ERRNO_MAX,
} BlessBootStatus;

BlessBootStatus bless_boot_status(void);

const char* bless_boot_status_to_string(BlessBootStatus) _const_;
BlessBootStatus bless_boot_status_from_string(const char *s) _pure_;
