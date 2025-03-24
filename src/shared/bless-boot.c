/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bless-boot.h"
#include "devnum-util.h"
#include "efi-api.h"
#include "efi-loader.h"
#include "efivars.h"
#include "fd-util.h"
#include "find-esp.h"
#include "path-util.h"
#include "string-table.h"

int acquire_path(char **path) {
        _cleanup_free_ char *esp_path = NULL, *xbootldr_path = NULL;
        dev_t esp_devid = 0, xbootldr_devid = 0;
        char **a;
        int r;

        if (!strv_isempty(path))
                return 0;

        r = find_esp_and_warn(NULL, NULL, /* unprivileged_mode= */ false, &esp_path, NULL, NULL, NULL, NULL, &esp_devid);
        if (r < 0 && r != -ENOKEY) /* ENOKEY means not found, and is the only error the function won't log about on its own */
                return r;

        r = find_xbootldr_and_warn(NULL, NULL, /* unprivileged_mode= */ false, &xbootldr_path, NULL, &xbootldr_devid);
        if (r < 0 && r != -ENOKEY)
                return r;

        if (!esp_path && !xbootldr_path)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "Couldn't find $BOOT partition. It is recommended to mount it to /boot.\n"
                                       "Alternatively, use --path= to specify path to mount point.");

        if (esp_path && xbootldr_path && !devnum_set_and_equal(esp_devid, xbootldr_devid)) /* in case the two paths refer to the same inode, suppress one */
                a = strv_new(esp_path, xbootldr_path);
        else if (esp_path)
                a = strv_new(esp_path);
        else
                a = strv_new(xbootldr_path);
        if (!a)
                return log_oom();

        strv_free_and_replace(path, a);

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *j = NULL;

                j = strv_join(path, ":");
                log_debug("Using %s as boot loader drop-in search path.", strna(j));
        }

        return 0;
}

static int parse_counter(
                const char *path,
                const char **p,
                uint64_t *ret_left,
                uint64_t *ret_done) {

        uint64_t left, done;
        const char *z, *e;
        size_t k;
        int r;

        assert(path);
        assert(p);

        e = *p;
        assert(e);
        assert(*e == '+');

        e++;

        k = strspn(e, DIGITS);
        if (k == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Can't parse empty 'tries left' counter from LoaderBootCountPath: %s",
                                       path);

        z = strndupa_safe(e, k);
        r = safe_atou64(z, &left);
        if (r < 0)
                return log_error_errno(r, "Failed to parse 'tries left' counter from LoaderBootCountPath: %s", path);

        e += k;

        if (*e == '-') {
                e++;

                k = strspn(e, DIGITS);
                if (k == 0) /* If there's a "-" there also needs to be at least one digit */
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Can't parse empty 'tries done' counter from LoaderBootCountPath: %s",
                                               path);

                z = strndupa_safe(e, k);
                r = safe_atou64(z, &done);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse 'tries done' counter from LoaderBootCountPath: %s", path);

                e += k;
        } else
                done = 0;

        if (done == 0)
                log_warning("The 'tries done' counter is currently at zero. This can't really be, after all we are running, and this boot must hence count as one. Proceeding anyway.");

        *p = e;

        if (ret_left)
                *ret_left = left;

        if (ret_done)
                *ret_done = done;

        return 0;
}


int acquire_boot_count_path(
                char **ret_path,
                char **ret_prefix,
                uint64_t *ret_left,
                uint64_t *ret_done,
                char **ret_suffix) {

        _cleanup_free_ char *path = NULL, *prefix = NULL, *suffix = NULL;
        const char *last, *e;
        uint64_t left, done;
        int r;

        r = efi_get_variable_path(EFI_LOADER_VARIABLE_STR("LoaderBootCountPath"), &path);
        if (r == -ENOENT)
                return -EUNATCH; /* in this case, let the caller print a message */
        if (r < 0)
                return log_error_errno(r, "Failed to read LoaderBootCountPath EFI variable: %m");

        if (!path_is_normalized(path))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Path read from LoaderBootCountPath is not normalized, refusing: %s",
                                       path);

        if (!path_is_absolute(path))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Path read from LoaderBootCountPath is not absolute, refusing: %s",
                                       path);

        last = last_path_component(path);
        e = strrchr(last, '+');
        if (!e)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Path read from LoaderBootCountPath does not contain a counter, refusing: %s",
                                       path);

        if (ret_prefix) {
                prefix = strndup(path, e - path);
                if (!prefix)
                        return log_oom();
        }

        r = parse_counter(path, &e, &left, &done);
        if (r < 0)
                return r;

        if (ret_suffix) {
                suffix = strdup(e);
                if (!suffix)
                        return log_oom();

                *ret_suffix = TAKE_PTR(suffix);
        }

        if (ret_path)
                *ret_path = TAKE_PTR(path);
        if (ret_prefix)
                *ret_prefix = TAKE_PTR(prefix);
        if (ret_left)
                *ret_left = left;
        if (ret_done)
                *ret_done = done;

        return 0;
}

int make_good(const char *prefix, const char *suffix, char **ret) {
        _cleanup_free_ char *good = NULL;

        assert(prefix);
        assert(suffix);
        assert(ret);

        /* Generate the path we'd use on good boots. This one is easy. If we are successful, we simple drop the counter
         * pair entirely from the name. After all, we know all is good, and the logs will contain information about the
         * tries we needed to come here, hence it's safe to drop the counters from the name. */

        good = strjoin(prefix, suffix);
        if (!good)
                return -ENOMEM;

        *ret = TAKE_PTR(good);
        return 0;
}

int make_bad(const char *prefix, uint64_t done, const char *suffix, char **ret) {
        _cleanup_free_ char *bad = NULL;

        assert(prefix);
        assert(suffix);
        assert(ret);

        /* Generate the path we'd use on bad boots. Let's simply set the 'left' counter to zero, and keep the 'done'
         * counter. The information might be interesting to boot loaders, after all. */

        if (done == 0) {
                bad = strjoin(prefix, "+0", suffix);
                if (!bad)
                        return -ENOMEM;
        } else {
                if (asprintf(&bad, "%s+0-%" PRIu64 "%s", prefix, done, suffix) < 0)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(bad);
        return 0;
}

static const char* const bless_boot_status_table[_BLESS_BOOT_STATUS_MAX] = {
        [BLESS_BOOT_STATUS_GOOD]         = "good",
        [BLESS_BOOT_STATUS_BAD]          = "bad",
        [BLESS_BOOT_STATUS_INTERMEDIATE] = "intermediate",
        [BLESS_BOOT_STATUS_CLEAN]        = "clean",
};

BlessBootStatus bless_boot_status(void) {
        int r;

        return BLESS_BOOT_STATUS_INTERMEDIATE;
}

DEFINE_STRING_TABLE_LOOKUP(bless_boot_status, BlessBootStatus);
