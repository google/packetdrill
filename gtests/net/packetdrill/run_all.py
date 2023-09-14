#!/usr/bin/env python3

"""Run packetdrill across a set of scripts."""

import argparse
import fnmatch
import os
import subprocess
import sys
import tempfile
import threading
import time


class TestSet(object):
  """All tests within a directory and its descendants."""

  def __init__(self, args):
    self.args = args
    self.tools_path = os.path.abspath('./packetdrill')
    self.default_args = '--send_omit_free'
    self.max_runtime = 180
    self.num_pass = 0
    self.num_fail = 0
    self.num_timedout = 0

  def FindTests(self, path='.'):
    """Return all *.pkt files in a given directory and its subdirectories."""
    if os.path.isfile(path):
      return [path]
    tests = []
    for dirpath, _, filenames in os.walk(path):
      for filename in fnmatch.filter(filenames, '*.pkt'):
        tests.append(dirpath + '/' + filename)
    return sorted(tests)

  def CmdTest(self, path, variant, extra_args=None):
    """Return a command to run a test using packetdrill in a subprocess."""
    bin_path = self.tools_path + '/' + 'packetdrill'
    nswrap_path = self.tools_path + '/' + 'in_netns.sh'

    path = os.path.abspath(path)
    execdir, basename = os.path.split(path)

    cmd = [nswrap_path, bin_path]
    cmd.extend(self.default_args.split())
    if extra_args is not None:
      cmd.extend(extra_args.split())
    cmd.append(basename)

    return (cmd, execdir, path, variant)

  def CmdTestIPv4(self, path):
    """Return a command to run a packetdrill test over ipv4."""
    return self.CmdTest(
        path, 'ipv4',
        ('--ip_version=ipv4 '
         '--local_ip=192.168.0.1 '
         '--gateway_ip=192.168.0.1 '
         '--netmask_ip=255.255.0.0 '
         '--remote_ip=192.0.2.1 '
         '-D TFO_COOKIE=3021b9d889017eeb '
         '-D CODE=host_unreachable '
         '-D CMSG_LEVEL_IP=SOL_IP '
         '-D CMSG_TYPE_RECVERR=IP_RECVERR')
    )

  def CmdTestIPv6(self, path):
    """Return a command to run a packetdrill test over ipv6."""
    return self.CmdTest(
        path, 'ipv6',
        ('--ip_version=ipv6 --mtu=1520 '
         '--local_ip=fd3d:0a0b:17d6::1 '
         '--gateway_ip=fd3d:0a0b:17d6:8888::1 '
         '--remote_ip=fd3d:fa7b:d17d::1 '
         '-D TFO_COOKIE=c1d1e9742a47a9bc '
         '-D CMSG_LEVEL_IP=SOL_IPV6 '
         '-D CMSG_TYPE_RECVERR=IPV6_RECVERR')
    )

  def CmdTestIPv4Mappedv6(self, path):
    """Return a command to run a packetdrill test over ipv4-mapped-v6."""
    return self.CmdTest(
        path, 'ipv4-mapped-v6',
        ('--ip_version=ipv4-mapped-ipv6 '
         '--local_ip=192.168.0.1 '
         '--gateway_ip=192.168.0.1 '
         '--netmask_ip=255.255.0.0 '
         '--remote_ip=192.0.2.1 '
         '-D TFO_COOKIE=3021b9d889017eeb '
         '-D CODE=host_unreachable '
         '-D CMSG_LEVEL_IP=SOL_IPV6 '
         '-D CMSG_TYPE_RECVERR=IPV6_RECVERR')
    )

  def CmdsTests(self, tests):
    """Run every test in tests in all three variants (v4, v6, v4-mapped-v6)."""
    cmds = []
    for test in tests:
      if not test.endswith('v6.pkt'):
        cmds.append(self.CmdTestIPv4(test))
        cmds.append(self.CmdTestIPv4Mappedv6(test))
      if not test.endswith('v4.pkt'):
        cmds.append(self.CmdTestIPv6(test))

    return cmds

  def Log(self, outfile, errfile):
    """Print a background process's stdout and stderr streams."""
    print('stdout: ')
    outfile.seek(0)
    sys.stdout.write(outfile.read())
    print('stderr: ')
    errfile.seek(0)
    sys.stderr.write(errfile.read())

  def StartTest(self, cmd, execdir, path, variant):
    """Run a packetdrill test"""
    outfile = tempfile.TemporaryFile(mode='w+')
    errfile = tempfile.TemporaryFile(mode='w+')

    time_start = time.time()
    process = subprocess.Popen(cmd, stdout=outfile, stderr=errfile, cwd=execdir)

    return (process, path, variant, outfile, errfile, time_start)

  def PollTest(self, process, path, variant, outfile, errfile, time_start, now):
    """Test whether a test has finished and if so record its return value."""
    if process.poll() is None:
      return False, now - time_start >= self.max_runtime

    if not process.returncode:
      self.num_pass += 1
      if self.args['verbose']:
        print('OK   [%s (%s)]' % (path, variant))
        if self.args['log_on_success']:
          self.Log(outfile, errfile)
    else:
      self.num_fail += 1
      if self.args['verbose']:
        print('FAIL [%s (%s)]' % (path, variant))
        if self.args['log_on_error']:
          self.Log(outfile, errfile)

    return True, False

  def StartPollTestSet(self, cmds):
    """Start and wait until all tests in procs have finished or until timeout."""
    max_in_parallel = 1 if self.args['serialized'] else self.args['max_in_parallel']
    if max_in_parallel == 0 or max_in_parallel > len(cmds):
      max_in_parallel = len(cmds)

    procs = []
    while len(procs) < max_in_parallel:
      procs.append(self.StartTest(*cmds.pop(0)))

    timedouts = []
    while procs:
      time.sleep(.1)
      now = time.time()
      for entry in procs:
        stopped, timedout = self.PollTest(*entry, now)

        if stopped or timedout:
          procs.remove(entry)
          if cmds:
            procs.append(self.StartTest(*cmds.pop(0)))
          if timedout:
            timedouts.append(entry)

    self.num_timedout = len(timedouts)
    for proc, path, variant, outfile, errfile, _ in timedouts:
      try:
        proc.kill()
      except:
        if self.args['verbose']:
          print('The test process has exited')
      if self.args['verbose']:
        print('KILL [%s (%s)]' % (path, variant))
        if self.args['log_on_error']:
          self.Log(outfile, errfile)

  def RunTests(self, path):
    """Find all packetdrill scripts in a path and run them."""
    tests = self.FindTests(path)

    time_start = time.time()
    cmds = self.CmdsTests(tests)
    self.StartPollTestSet(cmds)

    print(
        'Ran % 4d tests: % 4d passing, % 4d failing, % 4d timed out (%.2f sec): %s'     # pylint: disable=line-too-long
        % (self.num_pass + self.num_fail + self.num_timedout, self.num_pass,
           self.num_fail, self.num_timedout, time.time() - time_start, path))

  def NumErrors(self):
    """Return total number of failures."""
    return self.num_fail + self.num_timedout


class TestSetThread(threading.Thread):
  """A thread to run a test set in the background."""

  def __init__(self, args, path):
    super(TestSetThread, self).__init__()
    self.testset = TestSet(args)
    self.path = path

  def run(self):
    """Call the main method in this thread."""
    self.testset.RunTests(self.path)


class ParallelTestSet(object):
  """Run each subdirectory in a separate thread."""

  def FindSubDirs(self, path):
    """Get a list of subdirectories."""
    dirs = []
    children = os.listdir(path)
    for child in children:
      d = os.path.join(path, child)
      if os.path.isdir(d):
        dirs.append(d)
    return dirs

  def RunAll(self, args):
    """Construct a test set for each subdirectory and run them in parallel."""
    errors = 0

    if args['subdirs']:
      paths = self.FindSubDirs(args['path'])
    else:
      paths = [args['path']]

    threads = []
    for path in paths:
      t = TestSetThread(args, path)
      t.start()
      if not args['parallelize_dirs']:
        t.join()
      threads.append(t)

    for t in threads:
      t.join()
      errors += t.testset.NumErrors()

    return errors


def ParseArgs():
  """Parse commandline arguments."""
  args = argparse.ArgumentParser()
  args.add_argument('path', default='.', nargs='?')
  args.add_argument('-l', '--log_on_error', action='store_true',
                    help='requires verbose')
  args.add_argument('-L', '--log_on_success', action='store_true',
                    help='requires verbose')
  args.add_argument('-p', '--parallelize_dirs', action='store_true')
  args.add_argument('-P', '--max_in_parallel', metavar='N', type=int, default=0,
                    help="max number of tests running in parallel")
  args.add_argument('-s', '--subdirs', action='store_true')
  args.add_argument('-S', '--serialized', action='store_true')
  args.add_argument('-v', '--verbose', action='store_true')
  return vars(args.parse_args())


def main():
  args = ParseArgs()

  runner = ParallelTestSet()
  if runner.RunAll(args):
    sys.exit(1)


if __name__ == "__main__":
  main()
