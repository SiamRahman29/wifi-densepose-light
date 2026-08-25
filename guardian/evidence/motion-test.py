#!/usr/bin/env python3
"""Controlled A/B test: can the mesh actually distinguish stillness from motion?"""
import asyncio, json, statistics as st, sys, time, urllib.request
import websockets

PHASES = [
    ("A", "EMPTY / STILL", "Leave the room, or sit completely still. Do not move.", 30),
    ("B", "MOVING",        "Walk around the room continuously. Wave your arms.",   30),
    ("C", "EMPTY / STILL", "Stop. Sit completely still again.",                    30),
]

def nodes():
    try:
        with urllib.request.urlopen("http://localhost:3000/api/v1/nodes", timeout=3) as r:
            return {n["node_id"]: n["rssi_dbm"] for n in json.load(r)["nodes"]}
    except Exception:
        return {}

def subcarrier_variance(window):
    """Mean per-subcarrier variance across a window of amplitude vectors."""
    if len(window) < 4:
        return None
    L = min(len(f) for f in window)
    tot = 0.0
    for sc in range(L):
        col = [f[sc] for f in window]
        m = sum(col) / len(col)
        tot += sum((c - m) ** 2 for c in col) / len(col)
    return tot / L if L else None


async def record(seconds):
    feats, rssi_series = [], {}
    amp_win, csivar = {}, {}
    async with websockets.connect("ws://localhost:3001/ws/sensing", open_timeout=10) as ws:
        t0 = time.time(); last_poll = 0
        while time.time() - t0 < seconds:
            d = json.loads(await asyncio.wait_for(ws.recv(), timeout=8))
            f = d.get("features")
            if f: feats.append(f)
            for n in d.get("nodes", []):
                k = str(n["node_id"])
                a = n.get("amplitude")
                if a:
                    w = amp_win.setdefault(k, [])
                    w.append(a)
                    if len(w) > 24: w.pop(0)
                    v = subcarrier_variance(w)
                    if v is not None: csivar.setdefault(k, []).append(v)
            if time.time() - last_poll > 1.0:
                last_poll = time.time()
                for nid, r in nodes().items():
                    rssi_series.setdefault(nid, []).append(r)
            left = int(seconds - (time.time() - t0))
            print(f"\r    recording... {left:2d}s remaining ", end="", flush=True)
    print("\r" + " " * 45 + "\r", end="")
    return feats, rssi_series, csivar

def summarize(feats, rssi_series, csivar):
    def col(k): return [f[k] for f in feats if k in f]
    out = {}
    for k in ("motion_band_power", "variance", "breathing_band_power", "spectral_power"):
        v = col(k)
        if v: out[k] = {"mean": st.mean(v), "stdev": st.pstdev(v)}
    out["samples"] = len(feats)
    out["rssi_stdev_per_node"] = {n: (st.pstdev(v) if len(v) > 1 else 0.0)
                                  for n, v in rssi_series.items()}
    out["csi_variance_per_node"] = {n: st.mean(v) for n, v in csivar.items() if v}
    return out

async def main():
    print("\n" + "=" * 62)
    print("  MESH MOTION DISCRIMINATION TEST — 3 phases, 30s each")
    print("=" * 62)
    results = {}
    for tag, name, instruction, secs in PHASES:
        print(f"\n  PHASE {tag}: {name}")
        print(f"  >>> {instruction}")
        for i in range(5, 0, -1):
            print(f"\r    starting in {i}... ", end="", flush=True); time.sleep(1)
        print("\r" + " " * 30 + "\r", end="")
        feats, rssi, cv = await record(secs)
        results[tag] = summarize(feats, rssi, cv)
        print(f"    captured {results[tag]['samples']} frames")

    json.dump(results, open("/home/siam/Code/RuView/motion-test-results.json", "w"), indent=2)

    print("\n" + "=" * 62); print("  RESULTS"); print("=" * 62)
    still = [results["A"], results["C"]]
    moving = results["B"]
    for k in ("motion_band_power", "variance", "spectral_power"):
        if k not in moving: continue
        s = st.mean([r[k]["mean"] for r in still if k in r])
        m = moving[k]["mean"]
        ratio = (m / s) if s else float("inf")
        verdict = "DISCRIMINATES" if ratio > 1.5 or ratio < 0.67 else "no separation"
        print(f"  {k:22s} still={s:10.1f}  moving={m:10.1f}  ratio={ratio:5.2f}  {verdict}")
    print("\n  CSI SUBCARRIER VARIANCE per node  <-- primary detector")
    alln = sorted({n for t in "ABC" for n in results[t].get("csi_variance_per_node", {})})
    if not alln:
        print("    no amplitude data received - is the server the patched build?")
    for n in alln:
        a = results["A"]["csi_variance_per_node"].get(n)
        b = results["B"]["csi_variance_per_node"].get(n)
        c = results["C"]["csi_variance_per_node"].get(n)
        if None in (a, b, c): continue
        sm = (a + c) / 2
        r = b / sm if sm else float("inf")
        mark = "STRONG" if r > 2 else ("DISCRIMINATES" if r > 1.5 else "weak")
        print(f"    node {n}: still={sm:9.4f}  moving={b:9.4f}  ratio={r:5.2f}  {mark}")
    if alln:
        best = max(alln, key=lambda n: (results["B"]["csi_variance_per_node"].get(n, 0) /
                   max(1e-9, (results["A"]["csi_variance_per_node"].get(n, 0) +
                              results["C"]["csi_variance_per_node"].get(n, 0)) / 2)))
        print(f"    -> best node: {best}  (max-across-nodes is the right detector, not the mean)")

    print("\n  Per-node RSSI variability (stdev, dB):")
    for tag in ("A", "B", "C"):
        r = results[tag]["rssi_stdev_per_node"]
        row = "  ".join(f"n{n}={v:4.1f}" for n, v in sorted(r.items()))
        print(f"    phase {tag} ({'moving' if tag=='B' else 'still '}): {row}")
    print("\n  Raw numbers saved to motion-test-results.json")
    print("=" * 62 + "\n")

asyncio.run(main())
