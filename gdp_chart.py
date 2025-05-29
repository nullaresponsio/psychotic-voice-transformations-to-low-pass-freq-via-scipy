#!/usr/bin/env python3
import os, argparse, sys
import numpy as np, pandas as pd, matplotlib.pyplot as plt
from fredapi import Fred                                            # pip install fredapi

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('-o', '--output', help='base path for figure files')
    args = p.parse_args()
    out_base = args.output or 'real_gdp_analysis'

    fred = Fred(api_key="bf86cfde5e6fbdf02131a33470ae7901")
    ids = {
        'gdp'          : 'A191RL1Q225SBEA',
        'unemployment' : 'UNRATE',
        'spending'     : 'DPCERL1Q225SBEA',
        'industrial'   : 'INDPRO',
        'debt'         : 'GFDEBTN',
        'wealth'       : 'HNWBSL',
        'education'    : 'EDU685BPQ647N',
        'consumer_debt': 'TOTALSL'
    }

    series = {}
    for k, sid in ids.items():
        try:
            series[k] = fred.get_series(sid)
        except ValueError as e:
            sys.stderr.write(f"Warning: could not fetch series {sid} ({k}): {e}\n")

    df = pd.DataFrame(series).resample('QE').mean().dropna().iloc[-20:]
    y = df['gdp'].values

    features = [f for f in ['unemployment','spending','industrial','debt','wealth','education','consumer_debt'] if f in df.columns]
    X = df[features].values

    β, *_ = np.linalg.lstsq(X, y, rcond=None)
    dX = np.diff(X, axis=0)
    dY = np.diff(y)
    contrib = dX * β

    all_labels = [
        'Unemployment', 'Consumer Spending', 'Industrial Production',
        'Federal Debt', 'Household Wealth', 'Education Attainment',
        'Consumer Credit'
    ]
    labels = [lab for lab, f in zip(all_labels, ['unemployment','spending','industrial','debt','wealth','education','consumer_debt']) if f in df.columns]

    qtrs = df.index.to_period('Q').astype(str).tolist()
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(13.33, 11.25), dpi=288, sharex=True)
    ax1.axhline(0, ls='--', lw=1)
    ax1.plot(qtrs, y, 'o-', lw=2, label='GDP % chg')
    ax1.plot(qtrs[1:], dY, 'x--', lw=2, label='Δ GDP')
    for f, marker, lbl in zip(features, ['^-','h-','*-','.-','s-','d-','p-'], labels):
        ax1.plot(qtrs, df[f], marker, lw=2, label=lbl)
    ax1.set_title('Graph 1 – Real GDP and Component Series')
    ax1.set_ylabel('Percent / Index')
    ax1.grid(alpha=.3, ls='--')
    ax1.legend(fontsize='x-small')

    ax2.axhline(0, ls='--', lw=1)
    bottoms = np.zeros_like(dY)
    cols = ['tab:blue','tab:green','tab:red','tab:purple','tab:orange','tab:pink','tab:brown']
    for s, lbl, c in zip(contrib.T, labels, cols):
        ax2.bar(qtrs[1:], s, bottom=bottoms, width=.65, color=c, alpha=.6, label=lbl)
        bottoms += s
    ax2.plot(qtrs[1:], dY, 'k.--', label='Δ GDP net')
    ax2.set_title('Graph 2 – Quarter-to-Quarter Chain-Rule Decomposition')
    ax2.set_ylabel('Contribution')
    ax2.legend(fontsize='x-small')
    plt.setp(ax2.get_xticklabels(), rotation=45, ha='right', fontsize='x-small')
    fig.tight_layout()
    fig.savefig(f'{out_base}_graphs12.png', dpi=288)

    fig3, ax3 = plt.subplots(figsize=(13.33, 5), dpi=288)
    mean_abs = np.abs(contrib).mean(axis=0)
    order = np.argsort(mean_abs)[::-1]
    sw_fix = [False, True, True, True, True, True, True]
    for i in order:
        ax3.barh(labels[i], mean_abs[i], color='tab:green' if sw_fix[i] else 'tab:gray', alpha=.7)
    ax3.invert_yaxis()
    ax3.set_xlabel('Mean |Contribution|')
    ax3.set_title('Graph 3 – Ranked Drivers')
    fig3.tight_layout()
    fig3.savefig(f'{out_base}_graph3.png', dpi=288)

    product_ideas = [
        '', 'Personal Budget Coach', 'Supply-Chain SaaS',
        'Fiscal Transparency Dashboard', 'Micro-Investment Platform',
        'Upskilling Marketplace', 'Debt Reduction AI Coach'
    ]
    matrix = pd.DataFrame({
        'Driver': labels,
        'Effect': np.abs(contrib).mean(axis=0)[order],
        'Software_Addressable': [sw_fix[i] for i in order],
        'Proposed_Product': [product_ideas[i] for i in order]
    })
    matrix['Rank'] = matrix.index + 1
    matrix.to_csv(f'{out_base}_cause_effect_matrix.csv', index=False)

    corr = np.corrcoef(dY, np.diff(df['debt'].values))[0, 1]
    print(f'Correlation ΔGDP vs ΔDebt: {corr:.2f}')
    for lbl, coef in zip(labels, β):
        print(f'{lbl:22s}: {coef:+.4f}')
    print(matrix.to_string(index=False))

if __name__ == '__main__':
    main()
