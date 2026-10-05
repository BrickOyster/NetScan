"""Thesis figures from the re-analysis JSONs (small files; no raw CSV loading)."""
import json
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = "/home/dimit/data/git/NetScan/wiki/latex/figures/"
FILES = {2: "w2_d3", 3: "w3_d3", 4: "w4_d3", 5: "w5_d2", 6: "w6_d3", 7: "w7_d3", 8: "w8_cut"}
R = {w: json.load(open(f + ".json")) for w, f in FILES.items()}

BLUE, ORANGE, AQUA, NEUTRAL = "#2a78d6", "#eb6834", "#1baf7a", "#c9c8c2"
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
plt.rcParams.update({
    "font.family": "serif", "font.size": 10, "axes.edgecolor": INK2, "axes.labelcolor": INK,
    "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
    "savefig.dpi": 200, "savefig.bbox": "tight",
})

# ---- Figure 1: detection outcome per wave (100% stacked horizontal bars)
fig, ax = plt.subplots(figsize=(6.3, 3.1))
waves = list(range(2, 9))
cats = [("Never detected", "all_zero", NEUTRAL), ("Detected on first sample", "zero_lag", BLUE),
        ("Detected later", "later", ORANGE), ("Lag undetermined", "off_day_one", AQUA)]
left = np.zeros(len(waves))
for label, key, col in cats:
    vals = np.array([100 * R[w][key] / R[w]["total"] for w in waves])
    ax.barh(waves, vals, left=left, color=col, edgecolor="white", linewidth=1.2, height=0.72, label=label)
    if key == "all_zero":
        for y, v, l in zip(waves, vals, left):
            ax.text(l + v - 1.5, y, f"{v:.1f}%", va="center", ha="right", fontsize=8, color=INK)
    left += vals
ax.set_yticks(waves, [f"Wave {w}" for w in waves])
ax.invert_yaxis()
ax.set_xlim(0, 100)
ax.set_xlabel("Share of the wave's tracked IPs (%)")
ax.grid(axis="y", visible=False)
ax.legend(ncol=2, frameon=False, fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.17))
fig.savefig(OUT + "outcome_by_wave.png")

# ---- Figure 2: small multiples, share of IPs with >=1 detection per collection cycle, all waves
fig, axes = plt.subplots(2, 4, figsize=(6.6, 3.9), sharey=True)
axes.flat[-1].axis("off")
for ax, w in zip(axes.flat, waves):
    s = {int(k): v for k, v in R[w]["pct_series"].items()}
    x = sorted(s)
    ax.plot(x, [s[k] for k in x], color=BLUE, linewidth=1.6, marker="o", markersize=2.6)
    ax.set_title(f"Wave {w}  (Δ = {R[w]['delta']} d)", fontsize=8.5, color=INK)
    ax.set_xlim(-1, 42)
    ax.set_ylim(0, 26)
    ax.tick_params(labelsize=7.5)
for ax in list(axes[1][:3]) + [axes[0][3]]:
    ax.set_xlabel("Days since start", fontsize=8)
    ax.tick_params(labelbottom=True)
for ax in axes[:, 0]:
    ax.set_ylabel("IPs flagged (%)", fontsize=8)
fig.tight_layout(w_pad=0.6, h_pad=0.9)
fig.savefig(OUT + "detection_share_all_waves.png")

# ---- Figure 3: lag (days) for IPs first detected after the first sample, pooled over waves
lags = np.array(sum((R[w]["lag_days_later"] for w in waves), []))
fig, ax = plt.subplots(figsize=(6.3, 2.8))
bins = np.arange(0, lags.max() + 4, 3) - 0.5
ax.hist(lags, bins=bins, color=ORANGE, edgecolor="white", linewidth=1.0)
med = np.median(lags)
ax.axvline(med, color=INK2, linestyle="--", linewidth=1)
ax.text(med + 0.8, ax.get_ylim()[1] * 0.92, f"median {med:.0f} days", color=INK2, fontsize=8.5)
ax.set_xlabel("Days from sub-group start to first detection")
ax.set_ylabel("IPs")
ax.grid(axis="x", visible=False)
fig.savefig(OUT + "lag_days_hist.png")
print("n later", len(lags), "median", med, "IQR", np.percentile(lags, [25, 75]))
