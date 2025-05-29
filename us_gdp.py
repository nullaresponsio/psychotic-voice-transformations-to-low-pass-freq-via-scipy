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

    annotations = {idx: f"{txt} ({gdp_growth[idx]:.1f}%)" for idx, txt in raw_annotations.items()}

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

    print("=== EXPLANATIONS ===")
    print("Graph 1: headline GDP and component series; annotations flag notable shocks.")
    print("Graph 2: chain-rule bars show quarter-to-quarter drivers; stacked sign indicates lift vs drag.")
    print("Graph 3: average absolute contribution magnitudes rank systemic drivers and tags software-fixable ones.")
    print(f"Correlation ΔGDP vs ΔDebt: {corr:.2f}")
    print("β partial derivatives:")
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
                     arrowprops=dict(arrowstyle='->', lw=1), fontsize='x-small')

    ax1.set_ylabel("Percent / Growth Rate (Annualized)")
    ax1.set_xlabel("Quarter")
    ax1.grid(True, linestyle='--', alpha=0.4)
    ax1.legend(loc='upper left', fontsize='x-small')
    ax1.set_title("Graph 1 – US Real GDP & Key Metrics")

    ax2.axhline(0, linestyle='--', linewidth=1)
    ax2.plot(quarters[1:], derivative_gdp, marker='x', linestyle='--', linewidth=2, label='Δ GDP Growth')

    bottoms = np.zeros_like(derivative_gdp)
    colors = ['tab:blue', 'tab:orange', 'tab:green', 'tab:red', 'tab:purple']
    for series, name, col in zip(contrib, labels, colors):
        ax2.bar(quarters[1:], series, bottom=bottoms, label=name, width=0.6, color=col, alpha=0.6)
        bottoms += series

    ax2.set_ylabel("Quarterly Δ GDP Contributions")
    ax2.legend(loc='upper left', fontsize='x-small')
    ax2.set_xlabel("Quarter")
    ax2.set_xticks(range(len(quarters)))
    ax2.set_xticklabels(quarters, rotation=45, ha='right', fontsize='x-small')
    ax2.set_title("Graph 2 – Chain-Rule Decomposition of Δ GDP")

    explanation = ("Chain rule: ΔGDP ≈ Σβ·ΔX. Positive bars lift growth, negative bars drag. "
                   "Unemployment, inflation, spending dominate; debt effect small.")
    fig.text(0.5, 0.01, explanation, ha='center', va='bottom', fontsize='x-small')
    fig.tight_layout(rect=[0, 0.035, 1, 0.98])

    # --- Graph 3: systemic driver ranking ---
    mean_abs = np.mean(np.abs(contrib), axis=1)
    order = np.argsort(mean_abs)[::-1]
    fixable = [False, False, True, True, True]  # spending, industrial, debt seen as sw-fixable

    fig3, ax3 = plt.subplots(figsize=(13.33, 5), dpi=288)
    for idx in order:
        clr = 'tab:green' if fixable[idx] else 'tab:gray'
        ax3.barh(labels[idx], mean_abs[idx], color=clr, alpha=0.7)
    ax3.invert_yaxis()
    ax3.set_xlabel("Mean |Δ Contribution| to GDP")
    ax3.set_title("Graph 3 – Ranked Systemic Drivers (green = software-addressable)")
    txt = ("Top bars highlight systemic levers. Green items can be mitigated with software:\n"
           "• Consumer platforms to smooth demand\n"
           "• Industrial IoT & AI to optimize production\n"
           "• Fin-tech transparency to manage debt exposure")
    fig3.text(0.5, -0.12, txt, ha='center', va='top', fontsize='x-small', wrap=True)
    fig3.tight_layout(rect=[0, 0.05, 1, 0.95])

    base = args.output or 'real_gdp_analysis'
    fig.savefig(f"{base}.png", dpi=288)
    fig3.savefig(f"{base}_root_causes.png", dpi=288)

if __name__ == "__main__":
    main()
