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

    base_desc = {
        'Job'        : 'Workforce analytics & employment intelligence',
        'Budget'     : 'Consumer spending optimization platforms',
        'SupplyChain': 'Industrial and logistics orchestration software',
        'Debt'       : 'Fiscal health and debt management tools',
        'Wealth'     : 'Personal and household wealth solutions',
        'Upskill'    : 'Educational and skill-upgrading services',
        'Credit'     : 'Consumer credit analytics and management'
    }

    effects = np.abs(contrib).mean(axis=0)
    top_bases = []
    for idx in order:
        if sw_fix[idx]:
            b = roots_map.get(labels[idx], labels[idx].split()[0])
            if b not in top_bases:
                top_bases.append(b)
            if len(top_bases) == 5:
                break

    group_info = {}
    for base in top_bases:
        subtypes, exp = [], []
        for i in range(5):
            st = f"{base} {adjectives[i]} {suffixes[i]}"
            subtypes.append(st)
            exp.append(f"{adjectives[i]} {suffixes[i]} software for {base_desc[base].lower()}.")
        group_info[base] = (subtypes, exp)

    print('\n=== Product Groups by Top-Level Type ===\n')
    for base in sorted(group_info.keys()):
        print(f'{base}: {base_desc[base]}')
        subs, exps = group_info[base]
        for i, (st, ex) in enumerate(zip(subs, exps), 1):
            print(f'  {i}. {st} – {ex}')
        print()

    corr = np.corrcoef(dY, np.diff(df['debt'].values))[0, 1]
    print(f'Correlation ΔGDP vs ΔDebt: {corr:.2f}')
    for lbl, coef in zip(labels, β):
        print(f'{lbl:22s}: {coef:+.4f}')

    base_coef = {}
    for lbl, coef in zip(labels, β):
        base = roots_map.get(lbl, lbl.split()[0])
        base_coef[base] = coef

    explanation_map = {
        'Job'        : 'reducing unemployment, shortening job-search cycles, and matching labor supply to open roles',
        'Budget'     : 'helping households optimize discretionary spending, boosting aggregate demand',
        'SupplyChain': 'accelerating industrial throughput, lowering inventory lags, and trimming production costs',
        'Debt'       : 'improving fiscal health, lowering financing costs, and freeing resources for productive investment',
        'Wealth'     : 'growing household net worth, increasing confidence and capacity for consumption'
    }

    print('\n=== Partial-Derivative Effects and Monetization Narrative ===\n')
    for base in top_bases:
        coef = base_coef.get(base, 0.0)
        label = [k for k, v in roots_map.items() if v == base][0] if base in roots_map.values() else base
        expl = explanation_map.get(base, f'positively influencing {label.lower()}')
        print(f'{base}: dGDP/d{label} ≈ {coef:+.4f}')
        print(f'   The product family targets {expl}, which historical data suggest changes GDP by ~{coef:+.4f} pp for a one-unit improvement, holding other factors constant.')
        print(f'   Monetization strategy: tiered SaaS subscriptions, data-driven upsells (API access, advanced analytics), and performance-linked fees directly tied to realized {label.lower()} improvements.\n')

if __name__ == '__main__':
    main()
else:
    main()
