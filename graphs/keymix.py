#!/usr/bin/env python

import math
import os
import statistics
import sys

import matplotlib.pyplot as plt
import pandas as pd

from common import *

IMPLS = {
    'aesni-davies-meyer': {'name': 'Davies-Meyer', 'short-name': 'AES DM', 'block_size': 16, 'marker': 's', 'linestyle': 'dotted', 'color': 'orange'},
    'aesni-matyas-meyer-oseas': {'name': 'Matyas-Meyer-Oseas', 'short-name': 'AES MMO', 'block_size': 16, 'marker': 'D', 'linestyle': 'dotted', 'color': 'green'},
    # 'openssl-aes-128': {'name': 'AES-128-ECB', 'short-name': 'AES','block_size': 16, 'marker': 'o', 'linestyle': 'solid', 'color': 'royalblue'},
    # 'openssl-davies-meyer': {'name': 'Davies-Meyer', 'short-name': 'AES DM','block_size': 16, 'marker': 's', 'linestyle': 'solid', 'color': 'orange'},
    # 'openssl-matyas-meyer-oseas': {'name': 'Matyas-Meyer-Oseas', 'short-name': 'AES MMO','block_size': 16, 'marker': 'D', 'linestyle': 'solid', 'color': 'green'},
    # 'openssl-new-matyas-meyer-oseas': {'name': 'Matyas-Meyer-Oseas', 'short-name': 'AES MMO','block_size': 16, 'marker': 'D', 'linestyle': 'dashdot', 'color': 'green'},
    # 'wolfcrypt-aes-128': {'name': 'AES-128-ECB', 'short-name': 'AES','block_size': 16, 'marker': 'o', 'linestyle': 'dashed', 'color': 'royalblue'},
    # 'wolfcrypt-davies-meyer': {'name': 'Davies-Meyer', 'short-name': 'AES DM', 'block_size': 16, 'marker': 's', 'linestyle': 'dashed', 'color': 'orange'},
    # 'wolfcrypt-matyas-meyer-oseas': {'name': 'Matyas-Meyer-Oseas', 'short-name': 'AES MMO', 'block_size': 16, 'marker': 'D', 'linestyle': 'dashed', 'color': 'green'},
    # 'openssl-sha3-256': {'name': 'SHA3-256', 'short-name': 'SHA3-256', 'block_size': 32, 'marker': '<', 'linestyle': 'solid', 'color': 'red'},
    'openssl-blake2s': {'name': 'BLAKE2s', 'short-name': 'BLAKE2s', 'block_size': 32, 'marker': '1', 'linestyle': 'solid', 'color': 'purple'},
    'wolfcrypt-sha3-256': {'name': 'SHA3-256', 'short-name': 'SHA3-256', 'block_size': 32, 'marker': '<', 'linestyle': 'dashed', 'color': 'red'},
    # 'wolfcrypt-blake2s': {'name': 'BLAKE2s', 'short-name': 'BLAKE2s', 'block_size': 32, 'marker': '1', 'linestyle': 'dashed', 'color': 'purple'},
    'blake3-blake3': {'name': 'BLAKE3', 'short-name': 'BLAKE3', 'block_size': 32, 'marker': '2', 'linestyle': 'dotted', 'color': 'brown'},
    'aes-ni-mixctr': {'name': 'MixCTR', 'short-name': 'MixCTR', 'block_size': 48, 'marker': '*', 'linestyle': 'dotted', 'color': 'pink'},
    # 'openssl-mixctr': {'name': 'MixCTR', 'short-name': 'MixCTR', 'block_size': 48, 'marker': '*', 'linestyle': 'solid', 'color': 'pink'},
    # 'wolfcrypt-mixctr': {'name': 'MixCTR', 'short-name': 'MixCTR', 'block_size': 48, 'marker': '*', 'linestyle': 'dashed', 'color': 'pink'},
    # 'openssl-sha3-512': {'name': 'SHA3-512', 'short-name': 'SHA3-512', 'block_size': 64, 'marker': '>', 'linestyle': 'solid', 'color': 'grey'},
    'openssl-blake2b': {'name': 'BLAKE2b', 'short-name': 'BLAKE2b', 'block_size': 64, 'marker': '3', 'linestyle': 'solid', 'color': 'olive'},
    'wolfcrypt-sha3-512': {'name': 'SHA3-512', 'short-name': 'SHA3-512', 'block_size': 64, 'marker': '>', 'linestyle': 'dashed', 'color': 'grey'},
    # 'wolfcrypt-blake2b': {'name': 'BLAKE2b', 'short-name': 'BLAKE2b', 'block_size': 64, 'marker': '3', 'linestyle': 'dashed', 'color': 'olive'},
    # 'xkcp-xoodyak': {'name': 'Xoodyak', 'short-name': 'Xoodyak', 'block_size': 48, 'marker': 'p', 'linestyle': 'dotted', 'color': 'cyan'},
    # 'xkcp-xoofff-wbc': {'name': 'Xoofff-WBC', 'short-name': 'Xoofff-WBC', 'block_size': 48, 'marker': 'h', 'linestyle': 'dotted', 'color': 'lightcoral'},
    # 'openssl-shake256': {'name': 'SHAKE256', 'short-name': 'SHAKE256', 'block_size': 128, 'marker': '^', 'linestyle': 'solid', 'color': 'gold'},
    'wolfcrypt-shake256': {'name': 'SHAKE256', 'short-name': 'SHAKE256', 'block_size': 128, 'marker': '^', 'linestyle': 'dashed', 'color': 'gold'},
    'xkcp-turboshake256': {'name': 'TurboSHAKE256', 'short-name': 'TSHAKE256', 'block_size': 128, 'marker': 'P', 'linestyle': 'dotted', 'color': 'limegreen'},
    # 'openssl-shake128': {'name': 'SHAKE128', 'short-name': 'SHAKE128', 'block_size': 160, 'marker': 'v', 'linestyle': 'solid', 'color': 'turquoise'},
    'wolfcrypt-shake128': {'name': 'SHAKE128', 'short-name': 'SHAKE128', 'block_size': 160, 'marker': 'v', 'linestyle': 'dashed', 'color': 'turquoise'},
    'xkcp-turboshake128': {'name': 'TurboSHAKE128', 'short-name': 'TSHAKE128', 'block_size': 160, 'marker': 'X', 'linestyle': 'dotted', 'color': 'lightskyblue'},
    'xkcp-kangarootwelve': {'name': 'KangarooTwelve', 'short-name': 'K12', 'block_size': 160, 'marker': 'x', 'linestyle': 'dotted', 'color': 'navy'},
    # 'xkcp-kravette-wbc': {'name': 'Kravette-WBC', 'short-name': 'Kravette-WBC', 'block_size': 192, 'marker': '8', 'linestyle': 'dotted', 'color': 'magenta'},
}

FILE = os.path.realpath(os.path.join(__file__, '..', '..', 'data',
                                     'out-anthem-to-128-threads.csv')) # out-anthem.csv
OUTDIR = os.path.realpath(os.path.join(__file__, '..'))
TARGET_KEY_SIZE = 256 * 1024 * 1024
IS_WITH_LEGEND = True
X_THREAD_SCALE = 'log' # linear
Y_THREAD_SCALE = 'linear' # log
REPS = 5

df = pd.read_csv(FILE)
df = df[df.implementation.isin(IMPLS.keys())]
df.time = to_sec(df.time)
df['inv_time'] = 1 / df.time
fanouts = sorted(df.fanout.unique())

# Check for multiple instances of the same test in the input dataset
groups = df_groupby(df, ['key_size','outsize','internal_threads','external_threads','enc_mode','implementation','one_way_mix_type','fanout'])
groups = groups[groups['time_count'] != REPS]
if not groups.empty:
    with pd.option_context('display.max_rows', None, 'display.max_columns', None):
        print(f'ERROR: The following tests have more than {REPS} instances')
        print(groups[['key_size', 'internal_threads', 'implementation', 'fanout', 'time_count']])
    sys.exit(1)

# Keymix legend
if not IS_WITH_LEGEND:
    impls = [impl for impl in df.implementation.unique() if impl in IMPLS]
    legend = [IMPLS[impl]['name'] for impl in impls]

    handles = []
    plt.figure()
    for impl in impls:
        handle = plt.errorbar(0, 0, yerr=0, capsize=3, color=IMPLS[impl]['color'],
                              linestyle=IMPLS[impl]['linestyle'], marker=IMPLS[impl]['marker'],
                              markersize=8)
        handles.append(handle)

    obj = pltlegend(plt, handles, legend, width=4, ncol=7, inside=False, to_sort=True)
    export_legend(obj, os.path.join(OUTDIR, f'keymix-legend.pdf'))
    plt.close()

# Keymix time/speed vs key size (grouped by fanouts)
for fanout in fanouts:
    df_fanout = df[df.fanout == fanout]
    impls = list(df_fanout.implementation.unique())
    legend = [IMPLS[impl]['short-name'] for impl in impls if impl in IMPLS]

    # Time
    handles = []
    plt.figure()
    for impl in impls:
        if impl not in IMPLS:
            continue

        data = df_fanout[df_fanout.implementation == impl]
        data = data[data.internal_threads == 1]
        data = df_groupby(data, 'key_size')
        xs = [to_mib(x) for x in data.key_size if to_mib(x) < 3e4]
        ys = [y for y in data.time_mean[:len(xs)]]
        # Margins of error with 95% confidence interval
        errors = [1.960 * s/math.sqrt(REPS) for s in data.time_std[:len(xs)]]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, color=IMPLS[impl]['color'],
                              linestyle=IMPLS[impl]['linestyle'], marker=IMPLS[impl]['marker'],
                              markersize=8)
        handles.append(handle)

    if IS_WITH_LEGEND:
        pltlegend(plt, handles, legend, x0=-0.18, width=1.25, ncol=2, to_sort=True,
                  loc='upper left')
    plt.xlabel('Key size [MiB]')
    plt.xlim(6, 3e4)
    plt.xscale('log')
    plt.ylabel('Average time [s]')
    plt.yscale('log')
    plt.ylim(1e-2, 3e10)
    plt.savefig(os.path.join(OUTDIR, f'keymix-f{fanout}-time.pdf'),
                bbox_inches='tight', pad_inches=0)
    plt.close()

    # Speed
    handles = []
    plt.figure()
    for impl in impls:
        if impl not in IMPLS:
            continue

        data = df_fanout[df_fanout.implementation == impl]
        data = data[data.internal_threads == 1]
        data = df_groupby(data, 'key_size', agg='inv_time')
        xs = [to_mib(x) for x in data.key_size if to_mib(x) < 3e4]
        ys = [x * y for x, y in zip(xs, data.inv_time_mean)]
        # Margins of error with 95% confidence interval
        errors = [1.960 * to_mib(x) * s/math.sqrt(REPS) for x, s in zip(xs, data.inv_time_std[:len(xs)])]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, color=IMPLS[impl]['color'],
                              linestyle=IMPLS[impl]['linestyle'], marker=IMPLS[impl]['marker'],
                              markersize=8)
        handles.append(handle)

    if IS_WITH_LEGEND:
        pltlegend(plt, handles, legend, x0=-0.18, width=1.25, ncol=2, to_sort=True,
                  loc='upper left')
    plt.xlabel('Key size [MiB]')
    plt.xlim(6, 3e4)
    plt.xscale('log')
    plt.ylabel('Average speed [MiB/s]')
    plt.ylim(0, 350)
    plt.savefig(os.path.join(OUTDIR, f'keymix-f{fanout}-speed.pdf'),
                bbox_inches='tight', pad_inches=0)
    plt.close()

# Keymix time/speed vs #threads (grouped by fanout)
unit = 'MiB' if X_THREAD_SCALE == 'linear' or Y_THREAD_SCALE == 'log' else 'GiB'
to_unit = to_mib if X_THREAD_SCALE == 'linear' or Y_THREAD_SCALE == 'log' else to_gib

overall_thread_contributions = []
for fanout in fanouts:
    df_fanout = df[df.fanout == fanout]
    impls = list(df_fanout.implementation.unique())
    legend = [IMPLS[impl]['short-name'] for impl in impls if impl in IMPLS]

    # Time
    handles = []
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
        errors = [1.960 * s/math.sqrt(REPS) for s in data.time_std]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, color=IMPLS[impl]['color'],
                              linestyle=IMPLS[impl]['linestyle'], marker=IMPLS[impl]['marker'],
                              markersize=8)
        handles.append(handle)

    if IS_WITH_LEGEND:
        pltlegend(plt, handles, legend, x0=-0.18, width=1.25, ncol=2, to_sort=True,
                  loc='upper right')
    plt.xlabel('Number of threads')
    plt.xscale(X_THREAD_SCALE)
    plt.xticks(ticks=xs)
    plt.xticks(minor=True, ticks=[])
    ax = plt.gca()
    ax.get_xaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())
    plt.ylabel('Average time [s]')
    plt.ylim(bottom=0 if Y_THREAD_SCALE == 'linear' else 10**-1,
             top=100 if Y_THREAD_SCALE == 'linear' else 10**5)
    plt.yscale(Y_THREAD_SCALE)
    plt.savefig(os.path.join(OUTDIR, f'keymix-f{fanout}-threading-time.pdf'),
                bbox_inches='tight', pad_inches=0)
    plt.close()

    # Speed
    handles = []
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
        errors = [1.960 * to_unit(size) * s/math.sqrt(REPS) for s in data.inv_time_std]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, color=IMPLS[impl]['color'],
                              linestyle=IMPLS[impl]['linestyle'], marker=IMPLS[impl]['marker'],
                              markersize=8)
        handles.append(handle)

        print(f'=== {impl} ({to_mib(size):.1f} MiB)')
        for thr, speed in zip(xs, ys):
            print('Threads =', thr, end='\t')
            print('Speed   =', speed, end='\t')
            print(f'+{round(((speed - ys[0]) / ys[0]) * 100, 2):>6.2f}%', end='\t')
            thread_contribution = (speed - ys[0]) / ys[0] * 100 / max(1, thr - 1)
            print(f'+{round(thread_contribution, 2):>6.2f}%')
            if thr > 1:
                overall_thread_contributions.append(thread_contribution)

    if IS_WITH_LEGEND:
        pltlegend(plt, handles, legend, x0=-0.18, width=1.25, ncol=2, to_sort=True,
                  loc='upper left')
    plt.xlabel('Number of threads')
    plt.xscale(X_THREAD_SCALE)
    plt.xticks(ticks=xs)
    plt.xticks(minor=True, ticks=[])
    ax = plt.gca()
    ax.get_xaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())
    plt.ylabel(f'Average speed [{unit}/s]')
    plt.ylim(bottom=0 if Y_THREAD_SCALE == 'linear' else 1,
             top=1800 if X_THREAD_SCALE == 'linear' else (10**8 if Y_THREAD_SCALE == 'log' else 5))
    plt.yscale(Y_THREAD_SCALE)
    plt.savefig(os.path.join(OUTDIR, f'keymix-f{fanout}-threading-speed.pdf'),
                bbox_inches='tight', pad_inches=0)
    plt.close()
    print()

print('--- Overall')
print('Additional thread improvement', end='\t')
print(f'+{statistics.mean(overall_thread_contributions):>6.2f} (avg)', end='\t')
print(f'+{statistics.median(overall_thread_contributions):>6.2f} (median)')

# ============================== Degradation of speed for higher keys

ratios = []
for fanout in [2, 4, 8, 16]:
    print('--- Fanout', fanout)
    df_fanout = df[(df.fanout == fanout) & (df.internal_threads == 1)]
    impls = list(df_fanout.implementation.unique())
    for impl in impls:
        if impl not in IMPLS:
            continue

        data = df_fanout[df_fanout.implementation == impl]
        min_key = data.key_size.min()
        max_key = data.key_size.max()

        minkey_time = df_groupby(data[data.key_size == min_key], ['key_size']).time_mean[0]
        maxkey_time = df_groupby(data[data.key_size == max_key], ['key_size']).time_mean[0]

        minkey_speed = min_key / minkey_time
        maxkey_speed = max_key / maxkey_time

        print(f'{impl}', end='\n\t')
        print('Min key =', round(to_mib(min_key), 2), 'MiB', end='\t\t')
        print('Max key =', round(to_mib(min_key), 2), 'MiB', end='\t\t')

        ratio = (minkey_speed - maxkey_speed) / minkey_speed
        ratios.append(ratio)
        
        print('Speed ratio (decrement of maxkey over minkey) = ', round(ratio, 2), '%')

print(f'Highest ratio = {max(ratios)}%')
print(f'Lowest ratio =  {min(ratios)}%')
print(f'Average ratio = {sum(ratios) / len(ratios)}%')

# ============================== MixCTR speed vs AES-DM and AES-MMO

print()
print('=== MixCTR vs AES-DM vs AES-MMO')

data = df[df.internal_threads == 1]
data['speed'] = data['key_size'] / data['time']

data_dm = data[(data.fanout == 2) & (data.implementation == 'aesni-davies-meyer')]
data_mmo = data[(data.fanout == 2) & (data.implementation == 'aesni-matyas-meyer-oseas')]
data_mixctr = data[(data.fanout == 2) & (data.implementation == 'aes-ni-mixctr')]

speed_dm =     sum(data_dm.speed) / len(data_dm.speed)
speed_mmo =    sum(data_mmo.speed) / len(data_mmo.speed)
speed_mixctr = sum(data_mixctr.speed) / len(data_mixctr.speed)

print(f'MixCTR vs DM =  +{round((speed_mixctr / speed_dm - 1) * 100, 2)}%')
print(f'MixCTR vs MMO = +{round((speed_mixctr / speed_mmo - 1) * 100, 2)}%')

# ============================== MixCTR worst speed vs SHAKEx, BLAKEx, and SHA3 best speed


df['speed'] = df['key_size'] / df['time']
print()
print('=== MixCTR vs BLAKE/SHA3/SHAKE')
for fanout in [2, 4]:
    print('Fanout', fanout)
    data = df[(df.internal_threads == 1) & (df.fanout == fanout)]
    data_mixctr = data[data.implementation == 'aes-ni-mixctr'].speed
    speed_mixctr = sum(data_mixctr) / len(data_mixctr)

    max_speed_other = 0
    for impl in ['openssl-blake2s', 'wolfcrypt-sha3-256', 'blake3-blake3', 'openssl-blake2b', 'wolfcrypt-sha3-512', 'wolfcrypt-shake256', 'wolfcrypt-shake128']:
        data_other = data[data.implementation == impl].speed
        speed = sum(data_other) / len(data_other)
        max_speed_other = max(max_speed_other, speed)


    print('  MixCTR speed =', speed_mixctr)
    print('  Other speed  =', max_speed_other)
    print('Ratio (MixCTR / other) =', speed_mixctr / max_speed_other)
