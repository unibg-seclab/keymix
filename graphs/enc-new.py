import itertools
import math

import matplotlib.pyplot as plt
import pandas as pd

from common import *

# Common
FILE = 'data/enc-anthem.csv'
KEEP_FILES_MIB = [1, 10, 100, 1024, 10240, 102400]
ENC_MODES = {
    'ctr': {'name': 'Counter', 'color': 'tab:blue', 'marker': 'o'},
    'ctr-opt': {'name': 'Counter \w opt', 'color': 'tab:orange', 'marker': 's'},
    'ctr-ctr': {'name': 'Counter \w refresh', 'color': 'tab:green', 'marker': '^'},
    'ofb': {'name': 'Output Feedback', 'color': 'tab:red', 'marker': 'D'}
}

# Encryption time/speed vs resource size
IMPLEMENTATIONS = ['xkcp-turboshake128', 'openssl-matyas-meyer-oseas', 'openssl-aes-128']
MARKERS = ['o', 's', '^', 'D', '*', 'p', 'h', '8', 'v']

# Encryption modes time/speed comparison
TARGET_IMPLEMENTATIONS = ['openssl-aes-128']
TARGET_KEY_SIZE = 128 * 1024 * 1024 # 128 MiB
ENC_MODE_NAMES = [ENC_MODES[enc_mode]['name'] for enc_mode in ENC_MODES]


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
df['outsize_mib'] = to_mib(df.outsize)
df = df[df.outsize_mib.isin(KEEP_FILES_MIB)]
df.time = to_sec(df.time)
df['inv_time'] = 1 / df.time

# Encryption time/speed vs resource size (grouped by mode of operation and
# implementation)
for enc_mode, impl in itertools.product(ENC_MODES, IMPLEMENTATIONS):
    data = df[(df.enc_mode == enc_mode) & (df.implementation == impl)]

    if data.empty:
        continue

    key_sizes = sorted(data.key_size.unique())
    key_sizes_in_mib = [to_mib(k) for k in key_sizes]

    # Time
    plt.figure()
    for i, size in enumerate(key_sizes):
        grouped = df_groupby(data[data.key_size == size], 'outsize')
        xs = [to_mib(x) for x in grouped.outsize]
        ys = [y for y in grouped.time_mean]
        # Margins of error with 95% confidence interval
        errors = [1.960 * s/math.sqrt(5) for s in grouped.time_std]
        plt.errorbar(xs, ys, yerr=errors, capsize=3, marker=MARKERS[i], markersize=8)

    labels = [get_key_size_string(key_size) for key_size in key_sizes_in_mib]
    pltlegend(plt, labels, x0=-0.23, width=1.3)
    plt.xlabel('File size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average time [s]')
    plt.yscale('log')
    plt.savefig(f'graphs/enc-{enc_mode}-{impl}-time.pdf', bbox_inches='tight', pad_inches=0)
    plt.close()

    # Speed
    plt.figure()
    max_speed = 0
    for i, size in enumerate(key_sizes):
        grouped = df_groupby(data[data.key_size == size], 'outsize', agg='inv_time')
        xs = [to_mib(x) for x in grouped.outsize]
        ys = [x * y for x, y in zip(xs, grouped.inv_time_mean)]
        max_speed = max([max_speed] + ys)
        # Margins of error with 95% confidence interval
        errors = [1.960 * s/math.sqrt(5) for s in grouped.inv_time_std]
        plt.errorbar(xs, ys, yerr=errors, capsize=3, marker=MARKERS[i], markersize=8)

    pltlegend(plt, labels, x0=-0.23, width=1.3)
    plt.xlabel('File size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average speed [MiB/s]')
    plt.yscale('log')
    plt.savefig(f'graphs/enc-{enc_mode}-{impl}-speed.pdf', bbox_inches='tight', pad_inches=0)
    plt.close()

    print(f'--- {enc_mode} encryption speeds with {impl}')
    print(f'Max speed = {max_speed} [MiB/s]')

# Encryption modes time/speed comparison
for impl in TARGET_IMPLEMENTATIONS:
    data = df[df.implementation == impl]
    key_sizes = sorted(data.key_size.unique())

    plot_data = data[data.key_size == get_key_size(key_sizes, TARGET_KEY_SIZE)]

    if plot_data.empty:
        continue

    # Time
    plt.figure()
    for i, enc_mode in enumerate(ENC_MODES):
        grouped = df_groupby(plot_data[plot_data.enc_mode == enc_mode], 'outsize')
        xs = [to_mib(x) for x in grouped.outsize]
        ys = [y for y in grouped.time_mean]
        # Margins of error with 95% confidence interval
        errors = [1.960 * s/math.sqrt(5) for s in grouped.time_std]
        plt.errorbar(xs, ys, yerr=errors, capsize=3, color=ENC_MODES[enc_mode]['color'],
                     marker=ENC_MODES[enc_mode]['marker'], markersize=8)

    pltlegend(plt, ENC_MODE_NAMES, x0=-0.18, width=1.2, ncol=2)
    plt.xlabel('File size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average time [s]')
    plt.yscale('log')
    plt.savefig(f'graphs/enc-modes-{impl}-time.pdf', bbox_inches='tight',
                pad_inches=0)
    plt.close()

    # Speed
    plt.figure()
    for i, enc_mode in enumerate(ENC_MODES):
        grouped = df_groupby(plot_data[plot_data.enc_mode == enc_mode], 'outsize', agg='inv_time')
        xs = [to_mib(x) for x in grouped.outsize]
        ys = [x * y for x, y in zip(xs, grouped.inv_time_mean)]
        # Margins of error with 95% confidence interval
        errors = [1.960 * s/math.sqrt(5) for s in grouped.inv_time_std]
        plt.errorbar(xs, ys, yerr=errors, capsize=3, color=ENC_MODES[enc_mode]['color'],
                     marker=ENC_MODES[enc_mode]['marker'], markersize=8)

    pltlegend(plt, ENC_MODE_NAMES, x0=-0.18, width=1.2, ncol=2)
    plt.xlabel('File size [MiB]')
    plt.xscale('log')
    plt.ylabel('Average speed [MiB/s]')
    plt.yscale('log')
    plt.savefig(f'graphs/enc-modes-{impl}-speed.pdf', bbox_inches='tight', pad_inches=0)
    plt.close()
