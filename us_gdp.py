import argparse
import matplotlib.pyplot as plt
import numpy as np

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output', help='Path to save figure')
    args = parser.parse_args()

    quarters = [
        "Q1 2024", "Q2 2024", "Q3 2024", "Q4 2024",
        "Q1 2025", "Q2 2025", "Q3 2025", "Q4 2025"
    ]

    gdp_growth = [1.3, 3.0, 2.8, 2.3, -0.3, np.nan, np.nan, np.nan]
    debt_growth = [1.72, 0.71, 1.82, 2.15, np.nan, np.nan, np.nan, np.nan]
    unemployment_rate = [3.83, 4.00, 4.17, 4.13, 4.10, np.nan, np.nan, np.nan]
    pce_inflation = [2.7, 2.6, 2.3, 2.5, 2.5, np.nan, np.nan, np.nan]
    cpi_inflation = [np.nan] * len(quarters)
    core_cpi_inflation = [np.nan] * len(quarters)
    fed_funds_rate = [np.nan] * len(quarters)
    ten_year_treasury_yield = [np.nan] * len(quarters)
    consumer_sentiment = [np.nan] * len(quarters)
    manufacturing_pmi = [np.nan] * len(quarters)
    retail_sales_growth = [np.nan] * len(quarters)

    plt.figure(figsize=(12, 8))
    plt.plot(quarters, gdp_growth, marker='o', label="GDP Growth (%)")
    plt.plot(quarters, debt_growth, marker='s', label="Federal Debt Growth (%)")
    plt.plot(quarters, unemployment_rate, marker='^', label="Unemployment Rate (%)")
    plt.plot(quarters, pce_inflation, marker='d', label="PCE Inflation (% YoY)")
    plt.plot(quarters, cpi_inflation, marker='x', label="CPI Inflation (% YoY)")
    plt.plot(quarters, core_cpi_inflation, marker='.', label="Core CPI Inflation (% YoY)")
    plt.plot(quarters, fed_funds_rate, marker='*', label="Fed Funds Rate (%)")
    plt.plot(quarters, ten_year_treasury_yield, marker='P', label="10Y Treasury Yield (%)")
    plt.plot(quarters, consumer_sentiment, marker='h', label="Consumer Sentiment Index")
    plt.plot(quarters, manufacturing_pmi, marker='H', label="Manufacturing PMI")
    plt.plot(quarters, retail_sales_growth, marker='+', label="Retail Sales Growth (%)")
    plt.title("2024–2025 Real Economic Metrics by Quarter")
    plt.xlabel("Quarter")
    plt.ylabel("Value")
    plt.legend(ncol=2, fontsize="small")
    plt.grid(True)
    plt.tight_layout()

    if args.output:
        plt.savefig(args.output)
    else:
        plt.show()

if __name__ == "__main__":
    main()
