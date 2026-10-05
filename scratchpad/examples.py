"""Pick illustrative IP timelines from wave 4 (one load, ~100 MB)."""
import datetime as dt, collections, json
import reanalyse as ra
s = ra.load(4)
starts = {}
for i, v in s.items():
    g = i.split(":")[2]; starts[g] = min(starts.get(g, "9999"), v[0][0])
def tl(i):
    st = dt.date.fromisoformat(starts[i.split(":")[2]])
    return [((dt.date.fromisoformat(d) - st).days, sorted(p)) for d, _, _, p in s[i]]
cands = collections.defaultdict(list)
for i in s:
    t = tl(i)
    if len(t) != 14 or t[0][0] != 0: continue
    flags = [len(p) for _, p in t]
    engs = set().union(*[set(p) for _, p in t])
    if flags[0] >= 4 and all(f >= 3 for f in flags): cands["A_multi_persistent"].append(i)
    if flags[0] >= 1 and engs == {"Criminal IP"} and flags[-1] == 0 and flags[-2] == 0 and sum(flags) >= 3: cands["B_cip_expires"].append(i)
    if flags[0] == 0 and flags[1] == 0 and flags[2] == 0 and any(flags) and len(engs) == 1 and flags[-1] > 0: cands["C_late"].append(i)
    if flags[0] >= 1 and any(flags[k] == 0 and flags[k-1] > 0 and flags[k+1] > 0 for k in range(1, 13)) and len(engs) <= 2: cands["D_single_miss"].append(i)
    if sum(flags) == 0: cands["E_never"].append(i)
out = {}
for k, ids in sorted(cands.items()):
    i = sorted(ids)[len(ids) // 2]
    ip = i.split(":")[0].split(".")
    out[k] = {"masked": f"{ip[0]}.{ip[1]}.x.x", "port": i.split(":")[1], "n_candidates": len(ids), "timeline": tl(i)}
    print(k, len(ids), out[k]["masked"], [(d, len(p)) for d, p in out[k]["timeline"]], sorted(set().union(*[set(p) for _, p in out[k]["timeline"]])))
json.dump(out, open("examples_w4.json", "w"))
