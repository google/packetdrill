#!/usr/bin/python
#
# Copyright 2012 Google Inc. All Rights Reserved.

"""Sets sysctl values and writes a file that restores them.

The arguments are of the form "<proc-file>=<val>" separated by spaces.
The program first reads the current value of the proc-file and creates
a shell script named "/tmp/sysctl_restore_${PPID}.sh" which restores the values
when executed. It then sets the new values
"""

__author__ = ('brakmo@google.com (Lawrence Brakmo)')

import os
import subprocess
import sys

pppid = int(os.popen("ps -p %d -oppid=" % os.getppid()).read().strip())
filename = '/tmp/sysctl_restore_%d.sh' % pppid

# Open file for restoring sysctl values
restore_file = open(filename, 'w')
print('#!/bin/bash', file=restore_file)

for a in sys.argv[1:]:
  sysctl = a.split('=')
  # sysctl[0] contains the proc-file name, sysctl[1] the new value

  # read current value and add restore command to file
  cur_val = subprocess.check_output(['cat', sysctl[0]], universal_newlines=True)
  print('echo "%s" > %s' % (cur_val.strip(), sysctl[0]), file=restore_file)

  # set new value
  cmd = 'echo "%s" > %s' % (sysctl[1], sysctl[0])
  os.system(cmd)

os.system('chmod u+x %s' % filename)
