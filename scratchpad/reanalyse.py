"""Independent re-analysis of NetScan waves (read-only on the data).

Reproduces runanalysis.py semantics (detection = malicious|suspicious; EXPIRED_AFTER = 2; lifetime
accumulated per sample as +delta) so its output can be validated against out_logs.txt, while
allowing (a) a corrected per-wave delta and (b) a per-subgroup end-date cut-off.
Also emits the distributions the logs do not contain.

usage: reanalyse.py WAVE VARIANTS_JSON   (see __main__)
"""
import ast, csv, glob, json, sys, collections, datetime as dt
import numpy as np

csv.field_size_limit(sys.maxsize)
ROOT = "/home/dimit/data/git/NetScan/"
EXPIRED_AFTER = 2
POS = {"malicious", "suspicious"}
_intern = {}
FIX_TF = True
TF_FIXED = []


def I(x):
    return _intern.setdefault(x, x)


def load(wave, cutoff=None):
    files = glob.glob(f"{ROOT}group_wave_{wave}/**/report_????-??-??_*.csv", recursive=True)
    series = collections.defaultdict(list)  # id -> [(date, votes_pos, present_engines, positive_engines)]
    for f in files:
        rel = f[len(ROOT):]
        group = rel.split("/")[1].split("_")[1]
        date = rel.split("/")[-1].split("_")[1]
        if cutoff and date > cutoff[group]:
            continue
        for row in csv.DictReader(open(f)):
            try:
                tv = ast.literal_eval(row.get("total_votes", "{}"))
                rep = ast.literal_eval(row.get("report", "{}"))
            except Exception:
                continue
            ident = f"{row['IP']}:{row['Port']}:{group}"
            # Correction: vendors.py at 89583c8 (2025-10-29, fixed in 4e746de on 10-31) marked ThreatFox
            # "malicious" whenever tf_response["data"] was truthy -- including ThreatFox's own no_result
            # message. Restore those rows to harmless and remove the bogus vote.
            if FIX_TF and rep.get("ThreatFox", {}).get("category") == "malicious" and "'no_result'" in row.get("tf_response", ""):
                rep["ThreatFox"] = {"category": "harmless"}
                tv["malicious"] = tv.get("malicious", 0) - 1
                TF_FIXED.append(ident)
            present = I(tuple(sorted(rep)))
            pos = I(frozenset(e for e, r in rep.items() if str(r.get("category", "")).strip().lower() in POS))
            series[ident].append((I(date), tv.get("malicious", 0) + tv.get("suspicious", 0), present, pos))
    for v in series.values():
        v.sort(key=lambda x: x[0])
    return series


def poisson_binom(ps):
    d = np.array([1.0])
    for p in ps:
        d = np.convolve(d, [1 - p, p])
    return d


def analyse(wave, delta, full, cutoff=None):
    s = {}
    for ident, v in full.items():
        vv = [x for x in v if not cutoff or x[0] <= cutoff[ident.split(":")[2]]]
        if vv:
            s[ident] = vv
    starts = {}
    for ident, v in s.items():
        g = ident.split(":")[2]
        starts[g] = min(starts.get(g, "9999"), v[0][0])
    out = {"wave": wave, "delta": delta, "starts": starts}
    tot = len(s)
    allzero = sum(1 for v in s.values() if sum(x[1] for x in v) == 0)
    nz_first = later = off = 0
    lag_days_later = []
    for ident, v in s.items():
        if sum(x[1] for x in v) == 0:
            continue
        st = starts[ident.split(":")[2]]
        if v[0][0] == st and v[0][1] != 0:
            nz_first += 1
        elif v[0][0] == st:
            if any(x[1] > 0 for x in v[1:]):
                later += 1
                first = next(x[0] for x in v if x[1] > 0)
                lag_days_later.append((dt.date.fromisoformat(first) - dt.date.fromisoformat(st)).days)
        else:
            off += 1
    out.update(total=tot, all_zero=allzero, ever=tot - allzero, zero_lag=nz_first, later=later,
               off_day_one=off, lag_days_later=lag_days_later)

    # --- per-engine lifetime / percentage, faithful to runanalysis.compile_report_results
    life = collections.defaultdict(dict)
    censored = collections.defaultdict(dict)
    cnt = collections.defaultdict(collections.Counter)
    mal = collections.defaultdict(collections.Counter)
    for ident, v in s.items():
        st = dt.date.fromisoformat(starts[ident.split(":")[2]])
        nd = {}
        expired = set()
        for date, _, present, pos in v:
            k = (dt.date.fromisoformat(date) - st).days // delta
            for eng in present:
                cnt[eng][k] += 1
                if eng in expired:
                    continue
                if eng in pos:
                    mal[eng][k] += 1
                    life[eng][ident] = life[eng].get(ident, 0) + delta
                    nd[eng] = 0
                else:
                    if eng not in nd:
                        continue
                    life[eng][ident] += delta
                    nd[eng] += 1
                    if nd[eng] >= EXPIRED_AFTER:
                        life[eng][ident] -= delta
                        expired.add(eng)
        for eng in nd:
            censored[eng][ident] = eng not in expired
    engines = {}
    for eng in cnt:
        pct = [mal[eng][k] * 100.0 / cnt[eng][k] for k in sorted(cnt[eng]) if cnt[eng][k]]
        L = list(life[eng].values())
        engines[eng] = {
            "avg_life": float(np.mean(L)) if L else 0.0,
            "median_life": float(np.median(L)) if L else 0.0,
            "max_pct": max(pct) if pct else 0.0,
            "ever": len(L),
            "censored": int(sum(censored[eng].values())),
            "lives": L,
        }
    out["engines"] = engines
    sets = {e: set(d) for e, d in life.items() if d}
    alld = set().union(*sets.values())
    out["ever_report"] = len(alld)
    k = collections.Counter(sum(1 for S in sets.values() if i in S) for i in alld)
    out["exactly"] = dict(sorted(k.items()))

    N = len(alld)
    dist = poisson_binom([len(S) / N for S in sets.values()])
    d2 = poisson_binom([len(S) / tot for S in sets.values()])
    out["chance"] = {"engines": len(sets), "observed1": k[1] / N, "pred1_uncond": dist[1],
                     "pred1_cond": dist[1] / (1 - dist[0]), "p0": dist[0],
                     "pred1_pop_cond": d2[1] / (1 - d2[0]), "pred_ever_pop": 1 - d2[0]}

    standalone = {"AbuseIPDB", "ThreatFox", "Censys", "Cinsscore", "OpenPhish_pub"}
    sa = set().union(*[sets.get(e, set()) for e in standalone])
    vt = set().union(*[S for e, S in sets.items() if e not in standalone])
    out["provider"] = {"vt_union": len(vt), "standalone_union": len(sa),
                       "standalone_only": len(sa - vt), "vt_only": len(vt - sa), "both": len(vt & sa)}

    per = collections.defaultdict(lambda: [0, 0])
    for ident, v in s.items():
        st = dt.date.fromisoformat(starts[ident.split(":")[2]])
        for date, votes, _, _ in v:
            d = (dt.date.fromisoformat(date) - st).days
            per[d // delta * delta][0 if votes > 0 else 1] += 1
    out["pct_series"] = {d: m * 100.0 / (m + h) for d, (m, h) in sorted(per.items())}
    out["samples_per_ip"] = float(np.mean([len(v) for v in s.values()]))
    out["window_days"] = max((dt.date.fromisoformat(v[-1][0]) - dt.date.fromisoformat(starts[i.split(':')[2]])).days
                             for i, v in s.items())
    return out


def report(res):
    wave, delta = res["wave"], res["delta"]
    e = res["engines"]
    print(wave, delta, {k: res[k] for k in ("total", "all_zero", "ever", "ever_report", "zero_lag", "later", "off_day_one", "window_days")},
          res["exactly"], "CIP", round(e.get("Criminal IP", {}).get("avg_life", 0), 2), round(e.get("Criminal IP", {}).get("max_pct", 0), 2),
          "aM", round(e.get("alphaMountain.ai", {}).get("avg_life", 0), 2), "chance", {k: round(v, 3) for k, v in res["chance"].items()}, flush=True)


if __name__ == "__main__":
    # usage: reanalyse.py WAVE 'VARIANTS_JSON'  e.g. '[["d3", 3, null], ["cut", 3, {"u": "2026-09-12"}]]'
    wave = int(sys.argv[1])
    full = load(wave)  # raw CSVs are read exactly once per wave
    for name, delta, cutoff in json.loads(sys.argv[2]):
        res = analyse(wave, delta, full, cutoff)
        json.dump(res, open(f"w{wave}_{name}.json", "w"), default=float)
        report(res)
    print("ThreatFox rows corrected:", len(TF_FIXED), "distinct IDs:", len(set(TF_FIXED)), flush=True)
