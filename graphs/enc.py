#!/usr/bin/env python

import itertools
import math
import os
import sys

import matplotlib.pyplot as plt
import pandas as pd

from common import *


# Common
FILE = os.path.realpath(os.path.join(__file__, '..', '..', 'data', 'enc-anthem.csv'))
OUTDIR = os.path.realpath(os.path.join(__file__, '..'))
ENC_MODES = {
    'ctr': {'name': 'Counter', 'color': 'tab:blue', 'marker': 'o'},
    'ctr-opt': {'name': 'Counter w/ opt', 'color': 'tab:orange', 'marker': 's'},
    'ctr-ctr': {'name': 'Counter w/ refresh', 'color': 'tab:green', 'marker': '^'},
    'ofb': {'name': 'Output Feedback', 'color': 'tab:red', 'marker': 'D'}
}
IMPLEMENTATIONS = {
    # 'openssl-aes-128': {'name': 'AES-128-ECB', 'short-name': 'AES', 'block_size': 16, 'marker': 'o', 'linestyle': 'solid', 'color': 'royalblue'},
    # 'openssl-matyas-meyer-oseas': {'name': 'Matyas-Meyer-Oseas', 'short-name': 'AES MMO', 'block_size': 16, 'marker': 's', 'linestyle': 'solid', 'color': 'green'},
    # 'wolfcrypt-matyas-meyer-oseas': {'name': 'Matyas-Meyer-Oseas', 'short-name': 'AES MMO', 'block_size': 16, 'marker': 's', 'linestyle': 'dashed', 'color': 'green'},
    'aesni-matyas-meyer-oseas': {'name': 'Matyas-Meyer-Oseas', 'short-name': 'AES MMO', 'block_size': 16, 'marker': 's', 'linestyle': 'dotted', 'color': 'green'},
    'aes-ni-mixctr': {'name': 'MixCTR', 'short-name': 'MixCTR', 'block_size': 48, 'marker': '2', 'linestyle': 'dotted', 'color': 'pink'},
    'xkcp-turboshake256': {'name': 'TurboSHAKE256', 'short-name': 'TSHAKE256', 'block_size': 128, 'marker': 'P', 'linestyle': 'dotted', 'color': 'limegreen'},
    'xkcp-turboshake128': {'name': 'TurboSHAKE128', 'short-name': 'TSHAKE128', 'block_size': 160, 'marker': 'X', 'linestyle': 'dotted', 'color': 'lightskyblue'},
}
THREADS = 16
REPS = 5

# Encryption time/speed vs key size
RESOURCE_SIZE = 100 * 1024 * 1024 * 1024 # 100 GiB

# Encryption time/speed vs resource size
MARKERS = ['o', 's', '^', 'D', '*', 'p', 'h', '8', 'v']

# Encryption modes and mixing primitive time/speed comparison
IS_WITH_LEGEND = True
TARGET_KEY_SIZE = 256 * 1024 * 1024


# Select 1st key size >= target key size for the given implementation
def get_key_size(all_key_sizes, target_key_size):
    size = None
    for key_size in all_key_sizes:
        if key_size >= target_key_size:
            size = key_size
            break
    return size


def get_key_size_string(key_size):
    if key_size == int(key_size):
        return f'{int(key_size)}'
    else:
        return f'{round(key_size, 1)}'


df = pd.read_csv(FILE)
df = df[df.internal_threads == THREADS]
df.time = to_sec(df.time)
df['inv_time'] = 1 / df.time

# Check for multiple instances of the same test in the input dataset
groups = df_groupby(df, ['key_size','outsize','internal_threads','external_threads','enc_mode','implementation','one_way_mix_type','fanout'])
groups = groups[groups['time_count'] != REPS]
if not groups.empty:
    with pd.option_context('display.max_rows', None, 'display.max_columns', None):
        print(f'ERROR: The following tests have more than {REPS} instances')
        print(groups[['key_size', 'internal_threads', 'implementation', 'fanout', 'time_count']])
    sys.exit(1)

# Keep most performance results available on resource of 100 GiB
df_key_sizes = df[df.key_size <= 18000 * 1024 * 1024]

# Keep performance results available on all resource sizes
df = df[
    ((df.implementation == 'aesni-matyas-meyer-oseas') & (df.key_size <= 2048 * 1024 * 1024)) |
    ((df.implementation == 'aes-ni-mixctr') & (df.key_size <= 3072 * 1024 * 1024)) |
    ((df.implementation == 'xkcp-turboshake256') & (df.key_size <= 2048 * 1024 * 1024)) |
    ((df.implementation == 'xkcp-turboshake128') & (df.key_size <= 16000 * 1024 * 1024))
]

# Encryption legend
if not IS_WITH_LEGEND:
    impls = [impl for impl in df.implementation.unique() if impl in IMPLEMENTATIONS]
    legend = [IMPLEMENTATIONS[impl]['name'] for impl in impls]

    handles = []
    plt.figure()
    for impl in impls:
        handle = plt.errorbar(0, 0, yerr=0, capsize=3, color=IMPLEMENTATIONS[impl]['color'],
                              linestyle=IMPLEMENTATIONS[impl]['linestyle'],
                              marker=IMPLEMENTATIONS[impl]['marker'], markersize=8)
        handles.append(handle)

    obj = pltlegend(plt, handles, legend, width=2.3, ncol=4, inside=False, to_sort=True)
    export_legend(obj, os.path.join(OUTDIR, f'enc-legend.pdf'))
    plt.close()

# Encryption time/speed vs key size
for enc_mode in ENC_MODES:
    data = df_key_sizes[(df_key_sizes.enc_mode == enc_mode) & (df_key_sizes.outsize == RESOURCE_SIZE)]

    if data.empty:
        continue

    # Time
    plt.figure()
    handles = []
    labels = []
    for i, impl in enumerate(IMPLEMENTATIONS):
        plot_data = data[data.implementation == impl]

        if plot_data.empty:
            continue

        labels.append(f"Fanout {plot_data.fanout.unique()[0]:>2} ({IMPLEMENTATIONS[impl]['short-name']})")
        grouped = df_groupby(plot_data, 'key_size')
        xs = [to_mib(x) for x in grouped.key_size]
        ys = [y for y in grouped.time_mean]
        # Margins of error with 95% confidence interval
        errors = [1.960 * s/math.sqrt(REPS) for s in grouped.time_std]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, color=IMPLEMENTATIONS[impl]['color'],
                              linestyle=IMPLEMENTATIONS[impl]['linestyle'],
                              marker=IMPLEMENTATIONS[impl]['marker'], markersize=8)
        handles.append(handle)

    if IS_WITH_LEGEND:
        pltlegend(plt, handles, labels, x0=-0.22, width=1.3, ncol=1)
    plt.xlabel('Key size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average time [s]')
    plt.ylim(bottom=0, top=400)
    plt.savefig(os.path.join(OUTDIR, f'enc-{enc_mode}-primitives-time-by-key-size.pdf'),
                bbox_inches='tight', pad_inches=0)
    plt.close()

    # Speed
    plt.figure()
    handles = []
    labels = []
    for i, impl in enumerate(IMPLEMENTATIONS):
        plot_data = data[data.implementation == impl]

        if plot_data.empty:
            continue

        labels.append(f"Fanout {plot_data.fanout.unique()[0]:>2} ({IMPLEMENTATIONS[impl]['short-name']})")
        grouped = df_groupby(plot_data, 'key_size', agg='inv_time')
        xs = [to_mib(x) for x in grouped.key_size]
        ys = [to_mib(RESOURCE_SIZE) * y for y in grouped.inv_time_mean]
        # Margins of error with 95% confidence interval
        errors = [1.960 * to_mib(RESOURCE_SIZE) * s/math.sqrt(REPS) for s in grouped.inv_time_std]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, color=IMPLEMENTATIONS[impl]['color'],
                               linestyle=IMPLEMENTATIONS[impl]['linestyle'],
                               marker=IMPLEMENTATIONS[impl]['marker'], markersize=8)
        handles.append(handle)

    if IS_WITH_LEGEND:
        pltlegend(plt, handles, labels, x0=-0.22, width=1.3, ncol=1)
    plt.xlabel('Key size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average speed [MiB/s]')
    plt.ylim(bottom=0, top=1000)
    plt.savefig(os.path.join(OUTDIR, f'enc-{enc_mode}-primitives-speed-by-key-size.pdf'),
                bbox_inches='tight', pad_inches=0)
    plt.close()

# Encryption time/speed vs resource size
for enc_mode, impl in itertools.product(ENC_MODES, IMPLEMENTATIONS):
    data = df[(df.enc_mode == enc_mode) & (df.implementation == impl)]

    if data.empty:
        continue

    key_sizes = sorted(data.key_size.unique())
    key_sizes_in_mib = [to_mib(k) for k in key_sizes]
    labels = [get_key_size_string(key_size) for key_size in key_sizes_in_mib]

    # Configure colors with the use of a colormap
    norm = matplotlib.colors.LogNorm(vmin=8, vmax=2e4)
    sm = matplotlib.cm.ScalarMappable(norm=norm, cmap='viridis')

    # Time
    plt.figure()
    handles = []
    for i, size in enumerate(key_sizes):
        grouped = df_groupby(data[data.key_size == size], 'outsize')
        xs = [to_mib(x) for x in grouped.outsize]
        ys = [y for y in grouped.time_mean]
        # Margins of error with 95% confidence interval
        errors = [1.960 * s/math.sqrt(REPS) for s in grouped.time_std]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, color=sm.to_rgba(key_sizes_in_mib[i]),
                              marker=MARKERS[i], markersize=8)
        handles.append(handle)

    pltlegend(plt, handles, labels, ncol=2, expand=False, loc='upper left',
              title='Key sizes [MiB]')
    plt.xlabel('Resource size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average time [s]')
    plt.ylim(bottom=1e-3, top=1e7)
    plt.yscale('log')
    plt.savefig(os.path.join(OUTDIR, f'enc-{enc_mode}-{impl}-time.pdf'),
                bbox_inches='tight', pad_inches=0)
    plt.close()

    # Speed
    plt.figure()
    handles = []
    print(f'--- {enc_mode} encryption speeds with {impl}')
    for i, size in enumerate(key_sizes):
        grouped = df_groupby(data[data.key_size == size], 'outsize', agg='inv_time')
        xs = [to_mib(x) for x in grouped.outsize]
        ys = [x * y for x, y in zip(xs, grouped.inv_time_mean)]
        # Margins of error with 95% confidence interval
        errors = [1.960 * to_mib(x) * s/math.sqrt(REPS) for x, s in zip(grouped.outsize, grouped.inv_time_std)]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, color=sm.to_rgba(key_sizes_in_mib[i]),
                              marker=MARKERS[i], markersize=8)
        handles.append(handle)
        max_speed = max(ys)
        print(f'Key size = {to_mib(size):.1f} MiB \tMax speed = {max_speed} MiB/s')

    pltlegend(plt, handles, labels, ncol=2, expand=False, loc='lower right',
              title='Key sizes [MiB]')
    plt.xlabel('Resource size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average speed [MiB/s]')
    plt.ylim(bottom=1e-2, top=2e3)
    plt.yscale('log')
    plt.savefig(os.path.join(OUTDIR, f'enc-{enc_mode}-{impl}-speed.pdf'),
                bbox_inches='tight', pad_inches=0)
    plt.close()

# Encryption mixing primitive time/speed comparison vs resource size
for enc_mode in ENC_MODES:
    data = df[df.enc_mode == enc_mode]

    if data.empty:
        continue

    # Time
    plt.figure()
    handles = []
    labels = []
    for i, impl in enumerate(IMPLEMENTATIONS):
        plot_data = data[data.implementation == impl]
        key_sizes = sorted(plot_data.key_size.unique())
        plot_data = plot_data[plot_data.key_size == get_key_size(key_sizes, TARGET_KEY_SIZE)]

        if plot_data.empty:
            continue

        labels.append(IMPLEMENTATIONS[impl]['name'])
        grouped = df_groupby(plot_data, 'outsize')
        xs = [to_mib(x) for x in grouped.outsize]
        ys = [y for y in grouped.time_mean]
        # Margins of error with 95% confidence interval
        errors = [1.960 * s/math.sqrt(REPS) for s in grouped.time_std]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, color=IMPLEMENTATIONS[impl]['color'],
                              linestyle=IMPLEMENTATIONS[impl]['linestyle'],
                              marker=IMPLEMENTATIONS[impl]['marker'], markersize=8)
        handles.append(handle)

    if IS_WITH_LEGEND:
        pltlegend(plt, handles, labels, x0=-0.22, width=1.3, ncol=1, expand=False, to_sort=True)
    plt.xlabel('Resource size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average time [s]')
    plt.yscale('log')
    plt.savefig(os.path.join(OUTDIR, f'enc-{enc_mode}-primitives-time.pdf'),
                bbox_inches='tight', pad_inches=0)
    plt.close()

    # Speed
    plt.figure()
    handles = []
    labels = []
    for i, impl in enumerate(IMPLEMENTATIONS):
        plot_data = data[data.implementation == impl]
        key_sizes = sorted(plot_data.key_size.unique())
        plot_data = plot_data[plot_data.key_size == get_key_size(key_sizes, TARGET_KEY_SIZE)]

        if plot_data.empty:
            continue

        labels.append(IMPLEMENTATIONS[impl]['name'])
        grouped = df_groupby(plot_data, 'outsize', agg='inv_time')
        xs = [to_mib(x) for x in grouped.outsize]
        ys = [x * y for x, y in zip(xs, grouped.inv_time_mean)]
        # Margins of error with 95% confidence interval
        errors = [1.960 * to_mib(x) * s/math.sqrt(REPS) for x, s in zip(grouped.outsize, grouped.inv_time_std)]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, color=IMPLEMENTATIONS[impl]['color'],
                              linestyle=IMPLEMENTATIONS[impl]['linestyle'],
                              marker=IMPLEMENTATIONS[impl]['marker'], markersize=8)
        handles.append(handle)

    if IS_WITH_LEGEND:
        pltlegend(plt, handles, labels, x0=-0.22, width=1.3, ncol=1, expand=False, to_sort=True)
    plt.xlabel('Resource size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average speed [MiB/s]')
    plt.yscale('log')
    plt.savefig(os.path.join(OUTDIR, f'enc-{enc_mode}-primitives-speed.pdf'),
                bbox_inches='tight', pad_inches=0)
    plt.close()

# Encryption modes time/speed comparison vs resource size
for impl in IMPLEMENTATIONS:
    data = df[df.implementation == impl]
    key_sizes = sorted(data.key_size.unique())

    plot_data = data[data.key_size == get_key_size(key_sizes, TARGET_KEY_SIZE)]

    if plot_data.empty:
        continue

    # Time
    plt.figure()
    handles = []
    labels = []
    for i, enc_mode in enumerate(ENC_MODES):
        line_data = plot_data[plot_data.enc_mode == enc_mode]
        if line_data.empty:
            continue

        labels.append(ENC_MODES[enc_mode]['name'])
        grouped = df_groupby(line_data, 'outsize')
        xs = [to_mib(x) for x in grouped.outsize]
        ys = [y for y in grouped.time_mean]
        # Margins of error with 95% confidence interval
        errors = [1.960 * s/math.sqrt(REPS) for s in grouped.time_std]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, color=ENC_MODES[enc_mode]['color'],
                              marker=ENC_MODES[enc_mode]['marker'], markersize=8)
        handles.append(handle)

    pltlegend(plt, handles, labels, x0=-0.18, width=1.2, ncol=2)
    plt.xlabel('Resource size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average time [s]')
    plt.yscale('log')
    plt.savefig(os.path.join(OUTDIR, f'enc-modes-{impl}-time.pdf'),
                bbox_inches='tight', pad_inches=0)
    plt.close()

    # Speed
    plt.figure()
    handles = []
    labels = []
    for i, enc_mode in enumerate(ENC_MODES):
        line_data = plot_data[plot_data.enc_mode == enc_mode]
        if line_data.empty:
            continue

        labels.append(ENC_MODES[enc_mode]['name'])
        grouped = df_groupby(line_data, 'outsize', agg='inv_time')
        xs = [to_mib(x) for x in grouped.outsize]
        ys = [x * y for x, y in zip(xs, grouped.inv_time_mean)]
        # Margins of error with 95% confidence interval
        errors = [1.960 * s/math.sqrt(REPS) for x, s in zip(grouped.outsize, grouped.inv_time_std)]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, color=ENC_MODES[enc_mode]['color'],
                              marker=ENC_MODES[enc_mode]['marker'], markersize=8)
        handles.append(handle)

    pltlegend(plt, handles, labels, x0=-0.18, width=1.2, ncol=2)
    plt.xlabel('Resource size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average speed [MiB/s]')
    plt.yscale('log')
    plt.savefig(os.path.join(OUTDIR, f'enc-modes-{impl}-speed.pdf'),
                bbox_inches='tight', pad_inches=0)
    plt.close()
