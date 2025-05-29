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

    # --- new: emit every series id so logs always show the data sources
    print('\nFRED series IDs in use:')
    for k, sid in ids.items():
        print(f'  {k:15} : {sid}')
    print()

    series = {}
    for k, sid in ids.items():
        try:
            series[k] = fred.get_series(sid)
        except ValueError as e:
            sys.stderr.write(f"Warning: could not fetch series {sid} ({k}): {e}\n")

    df = pd.DataFrame(series).resample('QE').mean().dropna().iloc[-20:]
    y = df['gdp'].values
    features = [f for f in
                ['unemployment','spending','industrial','debt',
                 'wealth','education','consumer_debt']
                if f in df.columns]
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
    labels = [lab for lab, f in zip(all_labels,
               ['unemployment','spending','industrial','debt',
                'wealth','education','consumer_debt']) if f in df.columns]

    roots_map = {
        'Unemployment': 'Job',
        'Consumer Spending': 'Budget',
        'Industrial Production': 'SupplyChain',
        'Federal Debt': 'Debt',
        'Household Wealth': 'Wealth',
        'Education Attainment': 'Upskill',
        'Consumer Credit': 'Credit'
    }
    adjectives = ['AI','Smart','Quantum','Edge','Cloud','Mobile','Secure','Green','Social','Hyper']
    suffixes  = ['Platform','Dashboard','Marketplace','SaaS','Coach','Assistant','App','Service','Studio','Hub']

    base_desc = {
        'Job'        : 'Workforce analytics & employment intelligence',
        'Budget'     : 'Consumer spending optimization platforms',
        'SupplyChain': 'Industrial and logistics orchestration software',
        'Debt'       : 'Fiscal health and debt management tools',
        'Wealth'     : 'Personal and household wealth solutions',
        'Upskill'    : 'Educational and skill-upgrading services',
        'Credit'     : 'Consumer credit analytics and management'
    }

    mean_abs = np.abs(contrib).mean(axis=0)
    order = np.argsort(mean_abs)[::-1]
    sw_fix = [False, True, True, True, True, True, True]

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
        subs, exps = [], []
        for i in range(5):
            st = f"{base} {adjectives[i]} {suffixes[i]}"
            subs.append(st)
            exps.append(f"{adjectives[i]} {suffixes[i]} software for {base_desc[base].lower()}.")
        group_info[base] = (subs, exps)

    base_coef = {}
    for lbl, coef in zip(labels, β):
        base = roots_map.get(lbl, lbl.split()[0])
        base_coef[base] = coef

    records = []
    for base in top_bases:
        coef = base_coef.get(base, 0.0)
        subs, exps = group_info[base]
        for st, ex in zip(subs, exps):
            tam = 1e9 * (1 + 4 * rng.random())
            pen = 0.02 + 0.03 * rng.random()
            margin = 0.20 + 0.15 * rng.random()
            rev = tam * pen
            prof = rev * margin
            mcap = prof * 15
            records.append({
                'Base'      : base,
                'Subtype'   : st,
                'dGDP/dBase': coef,
                'TAM_USD'   : tam,
                'Pen'       : pen,
                'Margin'    : margin,
                'Revenue'   : rev,
                'Profit'    : prof,
                'MCap'      : mcap,
                'Expl'      : ex
            })

    df_sub = pd.DataFrame(records)

    print('\n=== Subtype-Level Effects and Economics ===\n')
    for base in top_bases:
        print(f'{base}: {base_desc[base]}')
        sub_df = df_sub[df_sub['Base'] == base]
        for _, r in sub_df.iterrows():
            print(f"  {r['Subtype']}: dGDP ≈ {r['dGDP/dBase']:+.4f}, "
                  f"TAM ${r['TAM_USD']/1e9:.2f}B, Pen {r['Pen']*100:.1f}%, "
                  f"Margin {r['Margin']*100:.1f}%, Rev ${r['Revenue']/1e6:.1f}M, "
                  f"Profit ${r['Profit']/1e6:.1f}M, Implied Cap ${r['MCap']/1e6:.1f}M – "
                  f"{r['Expl']}")
        print()

if __name__ == '__main__':
    main()
else:
    main()
