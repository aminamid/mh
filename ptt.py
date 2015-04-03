#!/usr/bin/env python

import sys
import os
import time
import pty

def my_pty_fork():

  try:
    ( cid, fd ) = pty.fork()
  except OSError as e:
    print str(e)

  print "%d - %d" % (fd, cid)

  if cid == 0:
    print "In Child Process: PID# %s" % os.getpid()
    print "%d - %d" % (fd, cid)

    sys.stdout.flush()
    try:
      os.execlp("python","ThePythonProgram","pyecho.py")
    except:
      print "Cannot spawn execlp..."
  else:
    print "In Parent Process: PID# %s" % os.getpid()
    print os.read(fd, 100)

    os.write(fd,"message one\n")
    print os.read(fd, 100)
    time.sleep(2)
    os.write(fd,"message two\n")
    print os.read(fd, 10000)
    time.sleep(2)
    print os.read(fd, 10000)


if __name__ == "__main__":
    my_pty_fork()
