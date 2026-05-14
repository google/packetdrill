#!/usr/bin/env python3
#
# Copyright 2012 Google Inc. All Rights Reserved.

"""Sets sysctl values and writes a file that restores them.

The arguments are of the form "<proc-file>=<val>" separated by spaces.
The program first reads the current value of the proc-file and creates
a shell script named "/tmp/sysctl_restore_${PACKETDRILL_PID}.sh" which
restores the values when executed. It then sets the new values.

PACKETDRILL_PID is set by packetdrill to the pid of itself, so a .pkt
file could restore sysctls by running `/tmp/sysctl_restore_${PPID}.sh`
at the end.
"""

__author__ = ('brakmo@google.com (Lawrence Brakmo)')

import os
import stat
import sys

filename = '/tmp/sysctl_restore_%s.sh' % os.environ['PACKETDRILL_PID']

# Open file for restoring sysctl values
restore_file = open(filename, 'w')
print('#!/bin/bash', file=restore_file)

for a in sys.argv[1:]:
  sysctl = a.split('=')
  # sysctl[0] contains the proc-file name, sysctl[1] the new value

  # read current value and add restore command to file
  with open(sysctl[0], 'r') as f:
    cur_val = f.read()
  print('echo "%s" > %s' % (cur_val.strip(), sysctl[0]), file=restore_file)

  # set new value
  with open(sysctl[0], 'w') as f:
    f.write(sysctl[1] + '\n')

os.chmod(filename, os.stat(filename).st_mode | stat.S_IXUSR)
