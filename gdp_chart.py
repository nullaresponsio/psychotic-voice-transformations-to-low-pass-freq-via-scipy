import argparse
import matplotlib.pyplot as plt
import numpy as np

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output', help='Path to save figure')
    args = parser.parse_args()

    quarters = [
        "Q1 2021", "Q2 2021", "Q3 2021", "Q4 2021",
        "Q1 2022", "Q2 2022", "Q3 2022", "Q4 2022",
        "Q1 2023", "Q2 2023", "Q3 2023", "Q4 2023",
        "Q1 2024", "Q2 2024", "Q3 2024", "Q4 2024",
        "Q1 2025"
    ]

    gdp_growth = [
        6.3, 6.5, 2.0, 6.9,
        -1.4, -0.9, 3.2, 2.9,
        1.1, 2.4, 4.9, 3.3,
        1.6, 3.0, 3.1, 2.4,
        -0.3
    ]

    federal_debt = [
        27.75, 28.38, 28.86, 29.09,
        30.04, 30.55, 31.03, 31.46,
        31.46, 31.76, 33.02, 33.94,
        34.29, 34.28, 34.40, 34.80,
        34.96
    ]

    unemployment_rate = [
        6.3, 5.9, 5.1, 4.2,
        3.6, 3.6, 3.5, 3.4,
        3.6, 3.5, 3.8, 3.7,
        3.8, 3.9, 3.8, 3.7,
        4.1
    ]

    pce_inflation = [
        1.6, 3.5, 4.0, 5.3,
        6.6, 7.1, 6.5, 5.2,
        4.5, 3.8, 3.6, 3.5,
        3.4, 2.8, 2.4, 2.3,
        2.7
    ]

    consumer_spending = [
        np.nan, np.nan, np.nan, np.nan,
        np.nan, np.nan, np.nan, np.nan,
        2.0, 1.6, 4.5, 1.1,
        1.8, 4.0, 3.5, 2.0,
        0.5
    ]

    industrial_production = [
        np.nan, np.nan, np.nan, np.nan,
        np.nan, np.nan, np.nan, np.nan,
        -0.2, 1.0, 0.5, -0.1,
        0.3, 1.2, 0.7, 0.4,
        -0.4
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

    derivative_gdp = np.diff(gdp_growth)
    derivative_debt = np.diff(federal_debt)
    corr = np.corrcoef(derivative_gdp, derivative_debt)[0,1]
    print(f"Correlation between Δ GDP Growth and Δ Federal Debt: {corr:.2f}")

    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax1.plot(quarters, gdp_growth, marker='o', linewidth=2, label='GDP Growth')
    ax1.plot(quarters[1:], derivative_gdp, marker='x', linestyle='--', linewidth=2, label='Δ GDP Growth')
    ax1.plot(quarters, unemployment_rate, marker='^', linewidth=2, label='Unemployment Rate')
    ax1.plot(quarters, pce_inflation, marker='p', linewidth=2, label='PCE Inflation')
    ax1.plot(quarters, consumer_spending, marker='h', linewidth=2, label='Consumer Spending Growth')
    ax1.plot(quarters, industrial_production, marker='*', linewidth=2, label='Industrial Production Growth')

    for idx, text in annotations.items():
        ax1.annotate(
            text,
            xy=(quarters[idx], gdp_growth[idx]),
            xytext=(idx, gdp_growth[idx] + 0.7),
            arrowprops=dict(arrowstyle='->', lw=1),
            fontsize='small'
        )
    ax1.set_xlabel("Quarter")
    ax1.set_ylabel("Percentage / Growth Rates")
    ax1.grid(True, linestyle='--', alpha=0.5)

    ax2 = ax1.twinx()
    ax2.plot(quarters, federal_debt, marker='s', linewidth=2, label='Federal Debt')
    ax2.plot(quarters[1:], derivative_debt, marker='d', linestyle='-.', linewidth=2, label='Δ Federal Debt')
    ax2.set_ylabel("Federal Debt (Trillions USD)")

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')

    plt.title("US Real GDP Growth, Federal Debt, and Related Metrics by Quarter")
    fig.tight_layout()

    if args.output:
        plt.savefig(args.output)
    else:
        plt.show()

if __name__ == "__main__":
    main()
