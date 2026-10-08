# A mixed workload: JSON encode/decode, regex, sorting, and Python-level
# per-record functions -- most of the time is in C, as in a typical service.
import json, re, time, hashlib
WORD = re.compile(r"[a-z]+")
def make(i):
    return {"id": i, "name": f"user{i}", "tags": ["a", "b", "c", str(i % 7)], "text": "lorem ipsum dolor sit amet " * 20}
def score(rec):
    words = WORD.findall(rec["text"])
    return len(words) + len(rec["tags"])
def digest(rec):
    return hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
def handle(blob):
    rec = json.loads(blob)
    return score(rec), digest(rec)
def run(n):
    blobs = [json.dumps(make(i)) for i in range(n)]
    out = [handle(b) for b in blobs]
    out.sort()
    return len(out)
run(100)
t = time.perf_counter()
n = run(20000)
dt = time.perf_counter() - t
print(f"BENCH mixed n={n} wall={dt:.4f}s")
