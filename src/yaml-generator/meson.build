# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_YAML') != 1
        subdir_done()
endif

executables += [
        generator_template + {
                'name' : 'systemd-yaml-generator',
                'sources' : files('yaml-generator.c'),
        },
]
