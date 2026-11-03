"""What tests/python_function_trace.rs traces: a known number of calls of each kind.

Waits for the file named by its first argument, so that the probes are in before
any of the calls. With `fork` and a third argument, it waits for the file named by
that argument, forks, and parent and child each make all of them. With `exec` and a
third argument, it makes them, then execs itself to wait for the file named by that
argument and make them again.
"""
import asyncio
import os
import sys
import threading
import time

forked = len(sys.argv) > 3 and sys.argv[2] == "fork"
if forked:
    while not os.path.exists(sys.argv[3]):
        time.sleep(0.01)
child = forked and os.fork()
print("ready", flush=True)
while not os.path.exists(sys.argv[1]):
    time.sleep(0.01)


def leaf(x):
    return x + 1


def mid(x):
    return leaf(x) + leaf(x)


def raiser(d):
    if d == 0:
        raise ValueError("boom")
    return raiser(d - 1)


def catcher():
    try:
        raiser(3)
    except ValueError:
        return leaf(0)


def gen(n):
    for i in range(n):
        yield i


class K:
    def __init__(self, v):
        self.v = v

    def method(self):
        return self.v

    def __getattr__(self, name):
        raise AttributeError(name)


def swallowed():
    k = K(1)
    return hasattr(k, "nope")


def via_c():
    return sorted([3, 1, 2], key=leaf)


async def co(n):
    await asyncio.sleep(0)
    return n


async def amain():
    return await asyncio.gather(co(1), co(2), co(3))


def worker():
    for _ in range(50):
        mid(1)


for _ in range(200):
    mid(1)
for _ in range(10):
    catcher()
assert sum(gen(30)) == 435
objs = [K(i) for i in range(20)]
assert sum(o.method() for o in objs) == 190
for _ in range(5):
    swallowed()
via_c()
asyncio.run(amain())
threads = [threading.Thread(target=worker, name=f"w{i}") for i in range(3)]
for t in threads:
    t.start()
for t in threads:
    t.join()
if forked and child:
    os.waitpid(child, 0)
if len(sys.argv) > 3 and sys.argv[2] == "exec":
    os.execv(sys.executable, [sys.executable, sys.argv[0], sys.argv[3]])
