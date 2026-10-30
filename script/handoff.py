#!/usr/bin/env python3
"""Receive listening sockets over a Unix socket and exec the server.

The parent sends the descriptors with SCM_RIGHTS. This process does not
need them inherited: run-program closes extra fds, and GitHub's SBCL did
that even with :preserve-fds. After dup2 onto 3, 4, ... the environment
matches systemd socket activation and the pid does not change across exec.
"""
import array
import os
import socket
import sys

path = os.environ.get("PAZUZU_HANDOFF_SOCK")
if not path or len(sys.argv) < 2:
    sys.stderr.write("usage: handoff.py PROGRAM ARG...\n")
    sys.exit(2)

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(path)
_data, ancdata, _flags, _addr = sock.recvmsg(16, 4096)
fds = []
for level, kind, payload in ancdata:
    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
        ints = array.array("i")
        ints.frombytes(payload[: len(payload) - (len(payload) % ints.itemsize)])
        fds.extend(int(fd) for fd in ints)
sock.close()
if not fds:
    sys.stderr.write("handoff received no descriptors\n")
    sys.exit(1)
# Place them at 3, 4, ... A dup that lands on the destination and is then
# closed would drop the socket before exec.
for index, src in enumerate(fds):
    dest = 3 + index
    if src != dest:
        os.dup2(src, dest)
        os.close(src)
os.environ["LISTEN_FDS"] = str(len(fds))
os.environ["LISTEN_FDNAMES"] = os.environ.get("PAZUZU_FDNAMES", "")
os.environ["LISTEN_PID"] = str(os.getpid())
sys.stdout.write("ready\n")
sys.stdout.flush()
os.execv(sys.argv[1], sys.argv[1:])
