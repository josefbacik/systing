import sys, time
def f(x):
    return x + 1
def run(n):
    s = 0
    for _ in range(n):
        s = f(s)
    return s
N = int(sys.argv[1]) if len(sys.argv) > 1 else 2_000_000
run(1000)
t = time.perf_counter()
run(N)
dt = time.perf_counter() - t
print(f"BENCH calls n={N} wall={dt:.4f}s per_call_ns={dt/N*1e9:.1f}")
