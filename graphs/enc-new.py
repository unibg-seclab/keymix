import itertools
import statistics

import matplotlib.pyplot as plt
import pandas as pd

from common import *

ENC_MODES = ['ctr', 'ctr-opt', 'ofb']
IMPLEMENTATIONS = ['xkcp-turboshake128', 'openssl-matyas-meyer-oseas', 'openssl-aes-128']
FILE = 'data/enc-anthem.csv'

df = pd.read_csv(FILE)
df['outsize_mib'] = to_mib(df.outsize)

keep_files_mib = [1, 10, 100, 1024, 10240, 102400]
df = df[df.outsize_mib.isin(keep_files_mib)]

markers = ["o", "s", "^", "D", "*", "p", "h", "8", "v"]

for enc_mode, impl in itertools.product(ENC_MODES, IMPLEMENTATIONS):
    data = df[(df.enc_mode == enc_mode) & (df.implementation == impl)]

    if data.empty:
        continue

    key_sizes = sorted(data.key_size.unique())
    key_sizes_in_mib = [to_mib(k) for k in key_sizes]

    plt.figure()
    for i, size in enumerate(key_sizes):
        grouped = df_groupby(data[data.key_size == size], 'outsize')
        xs = [to_mib(x) for x in grouped.outsize]
        ys = [to_sec(y) for y in grouped.time_mean]
        plt.plot(xs, ys, marker=markers[i], markersize=8)

    plt.xscale('log')
    plt.yscale('log')
    pltlegend(plt,
              [f'{int(k)} MiB' if k == int(k) else f'{round(k, 2)} MiB' for k in key_sizes_in_mib],
              x0=-0.155,
              width=1.3,
              is_with_legend=False)
    plt.xlabel('File size [MiB]')
    plt.ylabel('Average time [s]')
    plt.savefig(f'graphs/enc-{enc_mode}-{impl}-time.pdf', bbox_inches='tight', pad_inches=0)
    plt.close()

    max_speed = 0

    plt.figure()
    for i, size in enumerate(key_sizes):
        grouped = df_groupby(data[data.key_size == size], 'outsize')
        xs = [to_mib(x) for x in grouped.outsize]
        ys = [x / to_sec(y) for x, y in zip(xs, grouped.time_mean)]
        max_speed = max([max_speed] + ys)
        plt.plot(xs, ys, marker=markers[i], markersize=8)

    plt.xscale('log')
    plt.yscale('log')
    pltlegend(plt,
            [f'{int(k)} MiB' if k == int(k) else f'{round(k, 2)} MiB' for k in key_sizes_in_mib],
            x0=-0.155,
            width=1.3,
            is_with_legend=False)
    plt.xlabel('File size [MiB]')
    plt.ylabel('Average speed [MiB/s]')
    plt.savefig(f'graphs/enc-{enc_mode}-{impl}-speed.pdf', bbox_inches='tight', pad_inches=0)
    plt.close()

    print(f'--- {enc_mode} encryption speeds with {impl}')
    print(f"Max speed = {max_speed} [MiB/s]")
