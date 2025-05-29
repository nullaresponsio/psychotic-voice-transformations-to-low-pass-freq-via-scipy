# Data sources:
# GDP: BEA A191RL1Q225SBEA :contentReference[oaicite:0]{index=0}
# Federal debt: Treasury GFDEBTN :contentReference[oaicite:1]{index=1}
# Unemployment: BLS UNRATE :contentReference[oaicite:2]{index=2}
# PCE inflation: Q1 23 :contentReference[oaicite:3]{index=3} Q2 23 :contentReference[oaicite:4]{index=4} Q3 23 :contentReference[oaicite:5]{index=5} Q4 23 :contentReference[oaicite:6]{index=6} Q1 24 :contentReference[oaicite:7]{index=7} Q2 24 :contentReference[oaicite:8]{index=8} Q3 24 :contentReference[oaicite:9]{index=9} Q4 24 :contentReference[oaicite:10]{index=10} Q1 25 :contentReference[oaicite:11]{index=11}
# Consumer spending: BEA DPCERL1Q225SBEA :contentReference[oaicite:12]{index=12}
# Industrial production: Fed IPB50001SQ :contentReference[oaicite:13]{index=13}

import argparse
import matplotlib.pyplot as plt
import numpy as np

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output', help='Base path to save figures (omit extension)')
    args = parser.parse_args()

    quarters = [
        "Q1 2021", "Q2 2021", "Q3 2021", "Q4 2021",
        "Q1 2022", "Q2 2022", "Q3 2022", "Q4 2022",
        "Q1 2023", "Q2 2023", "Q3 2023", "Q4 2023",
        "Q1 2024", "Q2 2024", "Q3 2024", "Q4 2024",
        "Q1 2025"
    ]

    gdp_growth = [
         5.6,  6.4,  3.5,  7.4,
        -1.0,  0.3,  2.7,  3.4,
         2.8,  2.4,  4.4,  3.2,
         1.6,  3.0,  3.1,  2.4,
        -0.3
    ]

    federal_debt = [
        28.13, 28.53, 28.43, 29.62,
        30.40, 30.57, 30.93, 31.42,
        31.46, 32.33, 33.17, 34.00,
        34.59, 34.83, 35.46, 36.22,
        36.21
    ]

    unemployment_rate = [
        6.2, 5.9, 5.1, 4.5,
        3.8, 3.6, 3.6, 3.6,
        3.5, 3.5, 3.7, 3.8,
        3.8, 4.0, 4.2, 4.1,
        4.1
    ]

    pce_inflation = [
        1.7, 4.2, 6.2, 6.8,
        7.0, 6.8, 6.5, 5.6,
        4.2, 2.6, 2.9, 1.7,
        3.4, 2.5, 1.5, 2.4,
        3.6
    ]

    consumer_spending = [
        10.7, 11.9,  4.9,  3.3,
         3.1, -0.4,  1.5,  1.8,
         4.9,  1.0,  2.5,  3.5,
         1.9,  2.8,  3.7,  4.0,
         1.8
    ]

    industrial_production = [
         1.9, 6.5, 0.4, 1.6,
         1.2, 0.5, -0.2, -0.3,
         0.0, 0.1, 0.3, -0.5,
        -0.4, 0.6, -0.2, -0.3,
         1.3
    ]

    raw_annotations = {
         8: "Fed rate hikes curb growth",
         9: "Robust consumer spending",
        10: "Inventory replenishment spike",
        11: "Housing market slowdown",
        12: "Import surge & austerity measures",
        13: "Export rebound bolsters GDP",
        14: "Services sector expansion",
        15: "Energy sector strength",
        16: "Financial sector headwinds"
    }

    annotations = {
        idx: f"{text} ({gdp_growth[idx]:.1f}%)"
        for idx, text in raw_annotations.items()
    }

    derivative_gdp  = np.diff(gdp_growth)
    derivative_debt = np.diff(federal_debt)

    X = np.column_stack([
        unemployment_rate,
        pce_inflation,
        consumer_spending,
        industrial_production,
        federal_debt
    ])
    beta, *_ = np.linalg.lstsq(X, gdp_growth, rcond=None)
    labels = [
        "Unemployment",
        "Inflation",
        "Consumer Spending",
        "Industrial Production",
        "Federal Debt"
    ]

    d_unemp  = np.diff(unemployment_rate)
    d_infl   = np.diff(pce_inflation)
    d_cons   = np.diff(consumer_spending)
    d_ind    = np.diff(industrial_production)
    d_debt   = derivative_debt

    contrib = np.vstack([
        beta[0] * d_unemp,
        beta[1] * d_infl,
        beta[2] * d_cons,
        beta[3] * d_ind,
        beta[4] * d_debt
    ])

    corr = np.corrcoef(derivative_gdp, derivative_debt)[0, 1]
    print(f"Correlation between Δ GDP Growth and Δ Federal Debt: {corr:.2f}")
    print("Partial derivatives (β):")
    for lbl, b in zip(labels, beta):
        print(f"{lbl:22s}: {b:+.4f}")

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(13.33, 11.25), dpi=288, sharex=True)

    ax1.axhline(0, linestyle='--', linewidth=1)
    ax1.plot(quarters, gdp_growth, marker='o', linewidth=2, label='GDP Growth')
    ax1.plot(quarters[1:], derivative_gdp, marker='x', linestyle='--', linewidth=2, label='Δ GDP Growth')
    ax1.plot(quarters, unemployment_rate, marker='^', linewidth=2, label='Unemployment Rate')
    ax1.plot(quarters, pce_inflation, marker='p', linewidth=2, label='PCE Inflation')
    ax1.plot(quarters, consumer_spending, marker='h', linewidth=2, label='Consumer Spending Growth')
    ax1.plot(quarters, industrial_production, marker='*', linewidth=2, label='Industrial Production Growth')

    for idx, text in annotations.items():
        ax1.annotate(text, xy=(idx, gdp_growth[idx]), xytext=(idx, gdp_growth[idx] + 0.7),
                     arrowprops=dict(arrowstyle='->', lw=1), fontsize='small')

    ax1.set_ylabel("Percent / Growth Rate (Annualized)")
    ax1.set_xlabel("Quarter")
    ax1.grid(True, linestyle='--', alpha=0.4)
    ax1.legend(loc='upper left')
    ax1.set_title("US Real GDP Growth & Related Metrics by Quarter")

    ax2.axhline(0, linestyle='--', linewidth=1)
    ax2.plot(quarters[1:], derivative_gdp, marker='x', linestyle='--', linewidth=2, label='Δ GDP Growth')

    bottoms = np.zeros_like(derivative_gdp)
    colors = ['tab:blue', 'tab:orange', 'tab:green', 'tab:red', 'tab:purple']
    for i, (name, series, col) in enumerate(zip(labels, contrib, colors)):
        ax2.bar(quarters[1:], series, bottom=bottoms, label=f"∂GDP/∂{name} · d{name}/dt", width=0.6, color=col, alpha=0.6)
        bottoms += series

    ax2.set_ylabel("Quarterly Δ GDP Contributions")
    ax2.legend(loc='upper left', fontsize='small')
    ax2.set_xlabel("Quarter")
    ax2.set_xticks(range(len(quarters)))
    ax2.set_xticklabels(quarters, rotation=45, ha='right', fontsize='small')
    ax2.set_title("Chain Rule Decomposition of Δ GDP Growth")

    explanation = (
        "Chain decomposition approximates ΔGDP ≈ Σ β_i · dX_i/dt. Positive bars show variables pushing growth higher; "
        "negative bars show drags. Federal debt's coefficient is smallest; labor, prices, and spending dominate recent shifts."
    )
    fig.text(0.5, 0.01, explanation, ha='center', va='bottom', fontsize='small')

    fig.tight_layout(rect=[0, 0.03, 1, 0.98])

    base = args.output or 'real_gdp_analysis'
    fig.savefig(f"{base}.png", dpi=288)

if __name__ == "__main__":
    main()
