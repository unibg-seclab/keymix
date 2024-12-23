#!/usr/bin/env python

import itertools
import math
import os

import matplotlib.pyplot as plt
import pandas as pd

from common import *


# Common
FILE = os.path.realpath(os.path.join(__file__, '..', '..', 'data', 'enc-anthem.csv'))
OUTDIR = os.path.realpath(os.path.join(__file__, '..'))
ENC_MODES = {
    'ctr': {'name': 'Counter', 'color': 'tab:blue', 'marker': 'o'},
    'ctr-opt': {'name': 'Counter \w opt', 'color': 'tab:orange', 'marker': 's'},
    'ctr-ctr': {'name': 'Counter \w refresh', 'color': 'tab:green', 'marker': '^'},
    'ofb': {'name': 'Output Feedback', 'color': 'tab:red', 'marker': 'D'}
}
IMPLEMENTATIONS = {
    # 'openssl-aes-128': {'name': 'AES-128-ECB', 'block_size': 16, 'marker': 'o', 'linestyle': 'solid', 'color': 'royalblue'},
    # 'openssl-matyas-meyer-oseas': {'name': 'Matyas-Meyer-Oseas', 'block_size': 16, 'marker': 's', 'linestyle': 'solid', 'color': 'green'},
    'wolfcrypt-matyas-meyer-oseas': {'name': 'Matyas-Meyer-Oseas', 'block_size': 16, 'marker': 's', 'linestyle': 'dashed', 'color': 'green'},
    'aes-ni-mixctr': {'name': 'MixCtr', 'block_size': 48, 'marker': '2', 'linestyle': 'dotted', 'color': 'pink'},
    'xkcp-turboshake256': {'name': 'TurboSHAKE256', 'block_size': 128, 'marker': 'P', 'linestyle': 'dotted', 'color': 'limegreen'},
    'xkcp-turboshake128': {'name': 'TurboSHAKE128', 'block_size': 160, 'marker': 'X', 'linestyle': 'dotted', 'color': 'lightskyblue'},
}
THREADS = 16

# Encryption time/speed vs key size
RESOURCE_SIZE = 100 * 1024 * 1024 * 1024 # 100 GiB

# Encryption time/speed vs resource size
MARKERS = ['o', 's', '^', 'D', '*', 'p', 'h', '8', 'v']

# Encryption modes and mixing primitive time/speed comparison
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
        return f'{int(key_size)} MiB'
    else:
        return f'{round(key_size, 1)} MiB'


df = pd.read_csv(FILE)
df = df[df.internal_threads == THREADS]
df.time = to_sec(df.time)
df['inv_time'] = 1 / df.time

# Encryption time/speed vs key size
for enc_mode in ENC_MODES:
    data = df[(df.enc_mode == enc_mode) & (df.outsize == RESOURCE_SIZE)]

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

        labels.append(IMPLEMENTATIONS[impl]['name'])
        grouped = df_groupby(plot_data, 'key_size')
        xs = [to_mib(x) for x in grouped.key_size]
        ys = [y for y in grouped.time_mean]
        # Margins of error with 95% confidence interval
        errors = [1.960 * s/math.sqrt(5) for s in grouped.time_std]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, color=IMPLEMENTATIONS[impl]['color'],
                              linestyle=IMPLEMENTATIONS[impl]['linestyle'],
                              marker=IMPLEMENTATIONS[impl]['marker'], markersize=8)
        handles.append(handle)

    pltlegend(plt, handles, labels, x0=-0.22, width=1.3, ncol=2)
    plt.xlabel('Key size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average time [s]')
    plt.ylim(bottom=0)
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

        labels.append(IMPLEMENTATIONS[impl]['name'])
        grouped = df_groupby(plot_data, 'key_size', agg='inv_time')
        xs = [to_mib(x) for x in grouped.key_size]
        ys = [to_mib(RESOURCE_SIZE) * y for y in grouped.inv_time_mean]
        # Margins of error with 95% confidence interval
        errors = [1.960 * s/math.sqrt(5) for s in grouped.inv_time_std]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, color=IMPLEMENTATIONS[impl]['color'],
                               linestyle=IMPLEMENTATIONS[impl]['linestyle'],
                               marker=IMPLEMENTATIONS[impl]['marker'], markersize=8)
        handles.append(handle)

    pltlegend(plt, handles, labels, x0=-0.22, width=1.3, ncol=2)
    plt.xlabel('Key size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average speed [MiB/s]')
    plt.ylim(bottom=0)
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

    # Time
    plt.figure()
    handles = []
    for i, size in enumerate(key_sizes):
        grouped = df_groupby(data[data.key_size == size], 'outsize')
        xs = [to_mib(x) for x in grouped.outsize]
        ys = [y for y in grouped.time_mean]
        # Margins of error with 95% confidence interval
        errors = [1.960 * s/math.sqrt(5) for s in grouped.time_std]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, marker=MARKERS[i], markersize=8)
        handles.append(handle)

    pltlegend(plt, handles, labels, x0=-0.23, width=1.3)
    plt.xlabel('File size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average time [s]')
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
        errors = [1.960 * s/math.sqrt(5) for s in grouped.inv_time_std]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, marker=MARKERS[i], markersize=8)
        handles.append(handle)
        max_speed = max(ys)
        print(f'Key size = {to_mib(size):.1f} MiB \tMax speed = {max_speed} MiB/s')

    pltlegend(plt, handles, labels, x0=-0.23, width=1.3)
    plt.xlabel('File size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average speed [MiB/s]')
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
        errors = [1.960 * s/math.sqrt(5) for s in grouped.time_std]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, color=IMPLEMENTATIONS[impl]['color'],
                              linestyle=IMPLEMENTATIONS[impl]['linestyle'],
                              marker=IMPLEMENTATIONS[impl]['marker'], markersize=8)
        handles.append(handle)

    pltlegend(plt, handles, labels, x0=-0.22, width=1.3, ncol=2)
    plt.xlabel('File size [MiB]')
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
        errors = [1.960 * s/math.sqrt(5) for s in grouped.inv_time_std]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, color=IMPLEMENTATIONS[impl]['color'],
                              linestyle=IMPLEMENTATIONS[impl]['linestyle'],
                              marker=IMPLEMENTATIONS[impl]['marker'], markersize=8)
        handles.append(handle)

    pltlegend(plt, handles, labels, x0=-0.22, width=1.3, ncol=2)
    plt.xlabel('File size [MiB]')
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
        errors = [1.960 * s/math.sqrt(5) for s in grouped.time_std]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, color=ENC_MODES[enc_mode]['color'],
                              marker=ENC_MODES[enc_mode]['marker'], markersize=8)
        handles.append(handle)

    pltlegend(plt, handles, labels, x0=-0.18, width=1.2, ncol=2)
    plt.xlabel('File size [MiB]')
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
        errors = [1.960 * s/math.sqrt(5) for s in grouped.inv_time_std]
        handle = plt.errorbar(xs, ys, yerr=errors, capsize=3, color=ENC_MODES[enc_mode]['color'],
                              marker=ENC_MODES[enc_mode]['marker'], markersize=8)
        handles.append(handle)

    pltlegend(plt, handles, labels, x0=-0.18, width=1.2, ncol=2)
    plt.xlabel('File size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average speed [MiB/s]')
    plt.yscale('log')
    plt.savefig(os.path.join(OUTDIR, f'enc-modes-{impl}-speed.pdf'),
                bbox_inches='tight', pad_inches=0)
    plt.close()
