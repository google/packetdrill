#!/usr/bin/env python

import os
import sys

pppid = int(os.popen("ps -p %d -oppid=" % os.getppid()).read().strip())
restore_script_path = '/tmp/sysctl_restore_%d.sh' % pppid

restore_script = open(restore_script_path, 'w')
restore_script.write("#!/bin/sh\n")
restore_script.write("set -ex\n")

for a in sys.argv[1:]:
    sysctl = a.split('=')

    sysctl_path = sysctl[0]
    new_value = sysctl[1]
    if not os.path.exists(sysctl_path):
        continue
    with open(sysctl_path, "r") as sysctl_fd:
        old_val = sysctl_fd.read().strip()
    restore_script.write('echo {} > {}'.format(old_val, sysctl_path))

    cmd = 'echo {} > {}'.format(new_value, sysctl_path)
    os.system(cmd)

os.system('chmod u+x {}'.format(restore_script_path))
restore_script.close()
