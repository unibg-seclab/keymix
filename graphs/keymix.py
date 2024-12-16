#!/usr/bin/env python

import math
import os
import statistics

import matplotlib.pyplot as plt
import pandas as pd

from common import *

IMPLS = {
    # 'openssl-aes-128': {'name': 'AES-128-ECB', 'block_size': 16, 'marker': 'o', 'linestyle': 'solid', 'color': 'royalblue'},
    # 'openssl-davies-meyer': {'name': 'Davies-Meyer', 'block_size': 16, 'marker': 'v', 'linestyle': 'solid', 'color': 'orange'},
    # 'openssl-matyas-meyer-oseas': {'name': 'Matyas-Meyer-Oseas', 'block_size': 16, 'marker': '^', 'linestyle': 'solid', 'color': 'green'},
    # 'openssl-new-matyas-meyer-oseas': {'name': 'Matyas-Meyer-Oseas', 'block_size': 16, 'marker': '^', 'linestyle': 'dashdot', 'color': 'green'},
    # 'wolfcrypt-aes-128': {'name': 'AES-128-ECB', 'block_size': 16, 'marker': 'o', 'linestyle': 'dashed', 'color': 'royalblue'},
    'wolfcrypt-davies-meyer': {'name': 'Davies-Meyer', 'block_size': 16, 'marker': 'v', 'linestyle': 'dashed', 'color': 'orange'},
    'wolfcrypt-matyas-meyer-oseas': {'name': 'Matyas-Meyer-Oseas', 'block_size': 16, 'marker': '^', 'linestyle': 'dashed', 'color': 'green'},
    # 'openssl-sha3-256': {'name': 'SHA3-256', 'block_size': 32, 'marker': '<', 'linestyle': 'solid', 'color': 'red'},
    'openssl-blake2s': {'name': 'BLAKE2s', 'block_size': 32, 'marker': '>', 'linestyle': 'solid', 'color': 'purple'},
    'wolfcrypt-sha3-256': {'name': 'SHA3-256', 'block_size': 32, 'marker': '<', 'linestyle': 'dashed', 'color': 'red'},
    # 'wolfcrypt-blake2s': {'name': 'BLAKE2s', 'block_size': 32, 'marker': '>', 'linestyle': 'dashed', 'color': 'purple'},
    'blake3-blake3': {'name': 'BLAKE3', 'block_size': 32, 'marker': '1', 'linestyle': 'dotted', 'color': 'brown'},
    'aes-ni-mixctr': {'name': 'MixCtr', 'block_size': 48, 'marker': '2', 'linestyle': 'dotted', 'color': 'pink'},
    # 'openssl-mixctr': {'name': 'MixCtr', 'block_size': 48, 'marker': '2', 'linestyle': 'solid', 'color': 'pink'},
    # 'wolfcrypt-mixctr': {'name': 'MixCtr', 'block_size': 48, 'marker': '2', 'linestyle': 'dashed', 'color': 'pink'},
    # 'openssl-sha3-512': {'name': 'SHA3-512', 'block_size': 64, 'marker': '3', 'linestyle': 'solid', 'color': 'grey'},
    'openssl-blake2b': {'name': 'BLAKE2b', 'block_size': 64, 'marker': '4', 'linestyle': 'solid', 'color': 'olive'},
    'wolfcrypt-sha3-512': {'name': 'SHA3-512', 'block_size': 64, 'marker': '3', 'linestyle': 'dashed', 'color': 'grey'},
    # 'wolfcrypt-blake2b': {'name': 'BLAKE2b', 'block_size': 64, 'marker': '4', 'linestyle': 'dashed', 'color': 'olive'},
    # 'xkcp-xoodyak': {'name': 'Xoodyak', 'block_size': 48, 'marker': '8', 'linestyle': 'dotted', 'color': 'cyan'},
    # 'xkcp-xoofff-wbc': {'name': 'Xoofff-WBC', 'block_size': 48, 'marker': 's', 'linestyle': 'dotted', 'color': 'lightcoral'},
    # 'openssl-shake256': {'name': 'SHAKE256', 'block_size': 128, 'marker': 'p', 'linestyle': 'solid', 'color': 'gold'},
    'wolfcrypt-shake256': {'name': 'SHAKE256', 'block_size': 128, 'marker': 'p', 'linestyle': 'dashed', 'color': 'gold'},
    'xkcp-turboshake256': {'name': 'TurboSHAKE256', 'block_size': 128, 'marker': 'p', 'linestyle': 'dotted', 'color': 'limegreen'},
    # 'openssl-shake128': {'name': 'SHAKE128', 'block_size': 160, 'marker': 'P', 'linestyle': 'solid', 'color': 'turquoise'},
    'wolfcrypt-shake128': {'name': 'SHAKE128', 'block_size': 160, 'marker': 'P', 'linestyle': 'dashed', 'color': 'turquoise'},
    'xkcp-turboshake128': {'name': 'TurboSHAKE128', 'block_size': 160, 'marker': 'P', 'linestyle': 'dotted', 'color': 'lightskyblue'},
    'xkcp-kangarootwelve': {'name': 'KangarooTwelve', 'block_size': 160, 'marker': '*', 'linestyle': 'dotted', 'color': 'navy'},
    # 'xkcp-kravette-wbc': {'name': 'Kravette-WBC', 'block_size': 192, 'marker': '*', 'linestyle': 'dotted', 'color': 'magenta'},
}

FILE = os.path.realpath(os.path.join(__file__, '..', '..', 'data',
                                     'out-anthem-to-128-threads.csv')) # out-anthem.csv
OUTDIR = os.path.realpath(os.path.join(__file__, '..'))
THREAD_SCALE = 'log' # linear
TARGET_KEY_SIZE = 256 * 1024 * 1024

df = pd.read_csv(FILE)
df = df[df.implementation.isin(IMPLS.keys())]
df.time = to_sec(df.time)
df['inv_time'] = 1 / df.time
fanouts = sorted(df.fanout.unique())

# Keymix legend
impls = [impl for impl in df.implementation.unique() if impl in IMPLS]
legend = [IMPLS[impl]['name'] for impl in impls]
sorted_idx = sorted(range(len(legend)), key=lambda i: legend[i])
legend.sort()
plt.figure()
for i in sorted_idx:
    impl = impls[i]
    plt.errorbar(0, 0, yerr=0, capsize=3, color=IMPLS[impl]['color'],
                 linestyle=IMPLS[impl]['linestyle'], marker=IMPLS[impl]['marker'], markersize=8)
obj = pltlegend(plt, legend, width=4, ncol=7)
export_legend(obj, os.path.join(OUTDIR, f'legend.pdf'))
plt.close()

# Keymix time/speed vs key size (grouped by fanouts)
for fanout in fanouts:
    df_fanout = df[df.fanout == fanout]
    impls = list(df_fanout.implementation.unique())
    legend = [IMPLS[impl]['name'] for impl in impls if impl in IMPLS]

    # Time
    plt.figure()
    for impl in impls:
        if impl not in IMPLS:
            continue

        data = df_fanout[df_fanout.implementation == impl]
        data = data[data.internal_threads == 1]
        data = df_groupby(data, 'key_size')
        xs = [to_mib(x) for x in data.key_size]
        ys = [y for y in data.time_mean]
        # Margins of error with 95% confidence interval
        errors = [1.960 * s/math.sqrt(5) for s in data.time_std]
        plt.errorbar(xs, ys, yerr=errors, capsize=3, color=IMPLS[impl]['color'],
                     linestyle=IMPLS[impl]['linestyle'], marker=IMPLS[impl]['marker'], markersize=8)

    pltlegend(plt, legend, x0=-0.18, width=1.25, ncol=2, is_with_legend=False)
    plt.xlabel('Key size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average time [s]')
    plt.yscale('log')
    plt.ylim(1e-2, 1e3)
    plt.savefig(os.path.join(OUTDIR, f'keymix-f{fanout}-time.pdf'),
                bbox_inches='tight', pad_inches=0)
    plt.close()

    # Speed
    plt.figure()
    for impl in impls:
        if impl not in IMPLS:
            continue

        data = df_fanout[df_fanout.implementation == impl]
        data = data[data.internal_threads == 1]
        data = df_groupby(data, 'key_size', agg='inv_time')
        xs = [to_mib(x) for x in data.key_size]
        ys = [x * y for x, y in zip(xs, data.inv_time_mean)]
        # Margins of error with 95% confidence interval
        errors = [1.960 * s/math.sqrt(5) for s in data.inv_time_std]
        plt.errorbar(xs, ys, yerr=errors, capsize=3, color=IMPLS[impl]['color'],
                     linestyle=IMPLS[impl]['linestyle'], marker=IMPLS[impl]['marker'], markersize=8)

    pltlegend(plt, legend, x0=-0.18, width=1.25, ncol=2, is_with_legend=False)
    plt.xlabel('Key size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average speed [MiB/s]')
    plt.ylim(0, 200)
    plt.savefig(os.path.join(OUTDIR, f'keymix-f{fanout}-speed.pdf'),
                bbox_inches='tight', pad_inches=0)
    plt.close()

# Keymix time/speed vs #threads (grouped by fanout)
unit = 'MiB' if THREAD_SCALE == 'linear' else 'GiB'
to_unit = to_mib if THREAD_SCALE == 'linear' else to_gib

overall_thread_contributions = []
for fanout in fanouts:
    df_fanout = df[df.fanout == fanout]
    impls = list(df_fanout.implementation.unique())
    legend = [IMPLS[impl]['name'] for impl in impls if impl in IMPLS]

    # Time
    plt.figure()
    for impl in impls:
        if impl not in IMPLS:
            continue

        # Select 1st key sizes grater or equal to the target key size for the
        # given fanout and implementation pair
        size = IMPLS[impl]['block_size']
        while (size < TARGET_KEY_SIZE):
            size *= fanout

        data = df_fanout[(df_fanout.implementation == impl) & (df_fanout.key_size == size)]
        if data.empty:
            continue

        data = df_groupby(data, 'internal_threads')
        data = data[data.internal_threads <= 64] # filter out AMD SMT results
        xs = list(data.internal_threads)
        ys = [y for y in data.time_mean]
        # Margins of error with 95% confidence interval
        errors = [1.960 * s/math.sqrt(5) for s in data.time_std]
        plt.errorbar(xs, ys, yerr=errors, capsize=3, color=IMPLS[impl]['color'],
                     linestyle=IMPLS[impl]['linestyle'], marker=IMPLS[impl]['marker'], markersize=8)

    pltlegend(plt, legend, x0=-0.18, width=1.25, ncol=2, is_with_legend=False)
    plt.xlabel('Number of threads')
    plt.xscale(THREAD_SCALE)
    plt.xticks(ticks=xs)
    plt.xticks(minor=True, ticks=[])
    ax = plt.gca()
    ax.get_xaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())
    plt.ylabel('Average time [s]')
    plt.ylim(0, 50)
    plt.savefig(os.path.join(OUTDIR, f'keymix-f{fanout}-threading-time.pdf'),
                bbox_inches='tight', pad_inches=0)
    plt.close()

    # Speed
    plt.figure()
    print('--- Fanout', fanout)
    for impl in impls:
        if impl not in IMPLS:
            continue

        # Select 1st key sizes >100MiB for the given fanout and implementation
        # pair
        size = IMPLS[impl]['block_size']
        while (size < TARGET_KEY_SIZE):
            size *= fanout

        data = df_fanout[(df_fanout.implementation == impl) & (df_fanout.key_size == size)]
        if data.empty:
            continue

        data = df_groupby(data, 'internal_threads', agg='inv_time')
        data = data[data.internal_threads <= 64] # filter out AMD SMT results
        xs = list(data.internal_threads)
        ys = [to_unit(size) * y for y in data.inv_time_mean]
        # Margins of error with 95% confidence interval
        errors = [1.960 * s/math.sqrt(5) for s in data.inv_time_std]
        plt.errorbar(xs, ys, yerr=errors, capsize=3, color=IMPLS[impl]['color'],
                     linestyle=IMPLS[impl]['linestyle'], marker=IMPLS[impl]['marker'], markersize=8)

        print(f'=== {impl} ({to_mib(size):.1f} MiB)')
        for thr, speed in zip(xs, ys):
            print('Threads =', thr, end='\t')
            print('Speed   =', speed, end='\t')
            print(f'+{round(((speed - ys[0]) / ys[0]) * 100, 2):>6.2f}%', end='\t')
            thread_contribution = (speed - ys[0]) / ys[0] * 100 / max(1, thr - 1)
            print(f'+{round(thread_contribution, 2):>6.2f}%')
            if thr > 1:
                overall_thread_contributions.append(thread_contribution)

    pltlegend(plt, legend, x0=-0.18, width=1.25, ncol=2, is_with_legend=False)
    plt.xlabel('Number of threads')
    plt.xscale(THREAD_SCALE)
    plt.xticks(ticks=xs)
    plt.xticks(minor=True, ticks=[])
    ax = plt.gca()
    ax.get_xaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())
    plt.ylabel(f'Average speed [{unit}/s]')
    plt.ylim(top=1800 if THREAD_SCALE == 'linear' else 4)
    # plt.yscale('log')
    plt.savefig(os.path.join(OUTDIR, f'keymix-f{fanout}-threading-speed.pdf'),
                bbox_inches='tight', pad_inches=0)
    plt.close()
    print()

print('--- Overall')
print('Additional thread improvement', end='\t')
print(f'+{statistics.mean(overall_thread_contributions):>6.2f} (avg)', end='\t')
print(f'+{statistics.median(overall_thread_contributions):>6.2f} (median)')
