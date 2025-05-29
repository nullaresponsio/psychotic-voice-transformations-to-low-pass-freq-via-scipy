#!/usr/bin/env python3
import os, argparse, sys
import numpy as np, pandas as pd, matplotlib.pyplot as plt
from fredapi import Fred

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('-o', '--output', help='base path for figure files')
    p.add_argument('--seed', type=int, default=42)
    args = p.parse_args()
    out_base = args.output or 'real_gdp_analysis'
    rng = np.random.default_rng(args.seed)

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

    roots_map = {
        'Unemployment': 'Job',
        'Consumer Spending': 'Budget',
        'Industrial Production': 'SupplyChain',
        'Federal Debt': 'Debt',
        'Household Wealth': 'Wealth',
        'Education Attainment': 'Upskill',
        'Consumer Credit': 'Credit'
    }
    adjectives = [
        'AI','Smart','Quantum','Edge','Cloud','Mobile','Secure','Green','Social','Hyper',
        'Open','Voice','XR','Micro','Nano','Predictive','Realtime','LowCode','NoCode','Composable'
    ]
    suffixes = [
        'Platform','Dashboard','Marketplace','SaaS','Coach','Assistant','App','Service','Studio',
        'Hub','Exchange','Network','Analytics','Engine','API','Toolkit','OS','System','Portal',
        'Bot','Planner','Tracker','Optimizer','Simulator'
    ]
    product_ideas = []
    driver_idx = []
    for i, lbl in enumerate(labels):
        base = roots_map.get(lbl, lbl.split()[0])
        for adj in adjectives:
            for suf in suffixes:
                product_ideas.append(f"{base} {adj} {suf}")
                driver_idx.append(i)

    effects = np.abs(contrib).mean(axis=0)
    max_eff = effects.max()
    assumptions = {}
    for idea, idx in zip(product_ideas, driver_idx):
        eff = effects[idx]
        assumptions[idea] = {
            'tam': 1e9 * (1 + 4 * eff / max_eff),
            'penetration': 0.02 + 0.03 * rng.random(),
            'margin': 0.20 + 0.15 * rng.random()
        }

    matrix = pd.DataFrame({
        'Driver': [labels[i] for i in driver_idx],
        'Effect': [effects[i] for i in driver_idx],
        'Software_Addressable': [sw_fix[i] for i in driver_idx],
        'Proposed_Product': product_ideas
    })
    matrix['Rank'] = matrix.groupby('Driver')['Effect'].rank('first', ascending=False).astype(int)
    matrix['TAM_USD'] = matrix['Proposed_Product'].map(lambda x: assumptions[x]['tam'])
    matrix['Penetration'] = matrix['Proposed_Product'].map(lambda x: assumptions[x]['penetration'])
    matrix['Margin'] = matrix['Proposed_Product'].map(lambda x: assumptions[x]['margin'])
    matrix['Potential_Revenue_USD'] = matrix['TAM_USD'] * matrix['Penetration']
    matrix['Potential_Profit_USD'] = matrix['Potential_Revenue_USD'] * matrix['Margin']
    matrix['Derivative_Coefficient'] = [β[i] for i in driver_idx]
    matrix.to_csv(f'{out_base}_product_market_analysis.csv', index=False)

    corr = np.corrcoef(dY, np.diff(df['debt'].values))[0, 1]
    print(f'Correlation ΔGDP vs ΔDebt: {corr:.2f}')
    for lbl, coef in zip(labels, β):
        print(f'{lbl:22s}: {coef:+.4f}')
    print(f'\nGenerated {len(product_ideas)} product ideas (see CSV). Showing first 100:\n')
    print(matrix.head(100).to_string(index=False))

if __name__ == '__main__':
    main()
else:
    main()
