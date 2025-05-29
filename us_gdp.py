import argparse
import matplotlib.pyplot as plt
import numpy as np

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output', help='Path to save figure')
    args = parser.parse_args()

    quarters = [
        "Q1 2023", "Q2 2023", "Q3 2023", "Q4 2023",
        "Q1 2024", "Q2 2024", "Q3 2024", "Q4 2024",
        "Q1 2025"
    ]

    gdp_growth = [
        1.1, 2.4, 4.9, 3.3,
        1.6, 2.8, 2.8, 2.3,
        -0.3
    ]

    federal_debt = [
        31.46, 31.76, 33.02, 33.94,
        34.29, 34.28, 34.40, 34.80,
        34.96
    ]

    raw_annotations = {
        0: "Fed rate hikes curb growth",
        1: "Robust consumer spending",
        2: "Inventory replenishment spike",
        3: "Housing market slowdown",
        4: "Import surge & austerity measures",
        5: "Export rebound bolsters GDP",
        6: "Services sector expansion",
        7: "Energy sector strength",
        8: "Financial sector headwinds"
    }

    annotations = {
        idx: f"{text} ({gdp_growth[idx]:.1f}%)"
        for idx, text in raw_annotations.items()
    }

    derivative_gdp = np.diff(gdp_growth)
    derivative_debt = np.diff(federal_debt)
    corr = np.corrcoef(derivative_gdp, derivative_debt)[0,1]
    print(f"Correlation between Δ GDP Growth and Δ Federal Debt: {corr:.2f}")

    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax1.plot(quarters, gdp_growth, marker='o', linewidth=2, label='GDP Growth')
    ax1.plot(quarters[1:], derivative_gdp, marker='x', linestyle='--', linewidth=2, label='Δ GDP Growth')
    for idx, text in annotations.items():
        ax1.annotate(
            text,
            xy=(quarters[idx], gdp_growth[idx]),
            xytext=(idx, gdp_growth[idx] + 0.7),
            arrowprops=dict(arrowstyle='->', lw=1),
            fontsize='small'
        )
    ax1.set_xlabel("Quarter")
    ax1.set_ylabel("GDP Growth (%)")
    ax1.grid(True, linestyle='--', alpha=0.5)

    ax2 = ax1.twinx()
    ax2.plot(quarters, federal_debt, marker='s', linewidth=2, label='Federal Debt')
    ax2.plot(quarters[1:], derivative_debt, marker='d', linestyle='-.', linewidth=2, label='Δ Federal Debt')
    ax2.set_ylabel("Federal Debt (Trillions USD)")

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')

    plt.title("US Real GDP Growth and Federal Debt by Quarter")
    fig.tight_layout()

    if args.output:
        plt.savefig(args.output)
    else:
        plt.show()

if __name__ == "__main__":
    main()
