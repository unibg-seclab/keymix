import statistics

import matplotlib.pyplot as plt
import pandas as pd

from common import *

IMPLS = {
    'openssl-aes-128': {'name': 'AES-128-ECB', 'block_size': 16, 'marker': 'o', 'linestyle': 'solid', 'color': 'royalblue'},
    # 'openssl-davies-meyer': {'name': 'Davies-Meyer', 'block_size': 16, 'marker': 'v', 'linestyle': 'solid', 'color': 'orange'},
    'openssl-matyas-meyer-oseas': {'name': 'Matyas-Meyer-Oseas', 'block_size': 16, 'marker': '^', 'linestyle': 'solid', 'color': 'green'},
    # 'wolfcrypt-aes-128': {'name': 'AES-128-ECB', 'block_size': 16, 'marker': 'o', 'linestyle': 'dashed', 'color': 'royalblue'},
    'wolfcrypt-davies-meyer': {'name': 'Davies-Meyer', 'block_size': 16, 'marker': 'v', 'linestyle': 'dashed', 'color': 'orange'},
    # 'wolfcrypt-matyas-meyer-oseas': {'name': 'Matyas-Meyer-Oseas', 'block_size': 16, 'marker': '^', 'linestyle': 'dashed', 'color': 'green'},
    # 'openssl-sha3-256': {'name': 'SHA3-256', 'block_size': 32, 'marker': '<', 'linestyle': 'solid', 'color': 'red'},
    'openssl-blake2s': {'name': 'BLAKE2s', 'block_size': 32, 'marker': '>', 'linestyle': 'solid', 'color': 'purple'},
    'wolfcrypt-sha3-256': {'name': 'SHA3-256', 'block_size': 32, 'marker': '<', 'linestyle': 'dashed', 'color': 'red'},
    # 'wolfcrypt-blake2s': {'name': 'BLAKE2s', 'block_size': 32, 'marker': '>', 'linestyle': 'dashed', 'color': 'purple'},
    'blake3-blake3': {'name': 'BLAKE3', 'block_size': 32, 'marker': '1', 'linestyle': 'dotted', 'color': 'brown'},
    # 'aes-ni-mixctr': {'name': 'MixCtr', 'block_size': 48, 'marker': '2', 'linestyle': 'dotted', 'color': 'pink'},
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

FILE = 'data/out-anthem.csv'
TARGET_KEY_SIZE = 100 * 1024 * 1024

df = pd.read_csv(FILE)
df = df[df.implementation.isin(IMPLS.keys())]
fanouts = sorted(df.fanout.unique())

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
        ys = [to_sec(y) for y in data.time_mean]
        plt.loglog(xs, ys,
                   color=IMPLS[impl]['color'],
                   linestyle=IMPLS[impl]['linestyle'],
                   marker=IMPLS[impl]['marker'],
                   markersize=8)

    pltlegend(plt, legend, x0=-0.18, width=1.25, ncol=2)
    plt.xlabel('Key size [MiB]')
    plt.ylabel('Average time [s]')
    plt.ylim(1e-2, 1e3)
    plt.savefig(f'graphs/keymix-f{fanout}-time.pdf', bbox_inches='tight', pad_inches=0)
    plt.close()

    # Speed
    plt.figure()
    for impl in impls:
        if impl not in IMPLS:
            continue

        data = df_fanout[df_fanout.implementation == impl]
        data = data[data.internal_threads == 1]
        data = df_groupby(data, 'key_size')
        xs = [to_mib(x) for x in data.key_size]
        ys = [x / to_sec(y) for x, y in zip(xs, data.time_mean)]
        plt.plot(xs, ys,
                 color=IMPLS[impl]['color'],
                 linestyle=IMPLS[impl]['linestyle'],
                 marker=IMPLS[impl]['marker'],
                 markersize=8)

    pltlegend(plt, legend, x0=-0.18, width=1.25, ncol=2)
    plt.xlabel('Key size [MiB]')
    ax = plt.gca()
    ax.set_xscale('log')
    plt.ylabel('Average speed [MiB/s]')
    plt.ylim(0, 250)
    plt.savefig(f'graphs/keymix-f{fanout}-speed.pdf', bbox_inches='tight', pad_inches=0)
    plt.close()

# Keymix time/speed vs #threads (grouped by fanout)
overall_thread_contributions = []
for fanout in fanouts:
    df_fanout = df[df.fanout == fanout]
    impls = list(df_fanout.implementation.unique())
    legend = [IMPLS[impl]['name'] for impl in impls if impl in IMPLS]

    plt.figure()
    for impl in impls:
        if impl not in IMPLS:
            continue

        # Select 1st key sizes >100MiB for the given fanout and implementation
        # pair
        size = IMPLS[impl]['block_size']
        while (size < TARGET_KEY_SIZE):
            size *= fanout

        data = df_fanout[(df_fanout.implementation == impl) & (df_fanout.key_size == size)]
        data = df_groupby(data, 'internal_threads')
        xs = list(data.internal_threads)
        ys = [to_sec(y) for y in data.time_mean]
        plt.plot(xs, ys,
                 color=IMPLS[impl]['color'],
                 linestyle=IMPLS[impl]['linestyle'],
                 marker=IMPLS[impl]['marker'],
                 markersize=8)

    pltlegend(plt, legend, x0=-0.18, width=1.25, ncol=2)
    plt.xlabel('Number of threads')
    plt.xticks(ticks=xs)
    plt.ylabel('Average time [s]')
    plt.ylim(0, 25)
    plt.savefig(f'graphs/keymix-f{fanout}-threading-time.pdf', bbox_inches='tight', pad_inches=0)
    plt.close()

    print('-------------- Fanout', fanout)
    plt.figure()
    for impl in impls:
        if impl not in IMPLS:
            continue

        # Select 1st key sizes >100MiB for the given fanout and implementation
        # pair
        size = IMPLS[impl]['block_size']
        while (size < TARGET_KEY_SIZE):
            size *= fanout

        data = df_fanout[(df_fanout.implementation == impl) & (df_fanout.key_size == size)]
        data = df_groupby(data, 'internal_threads')
        xs = list(data.internal_threads)
        ys = [to_mib(size) / to_sec(y) for y in data.time_mean]

        print('=== For impl', impl)
        for thr, speed in zip(xs, ys):
            print('Threads =', thr, end='\t')
            print('Speed   =', speed, end='\t')
            print(f'+{round(((speed - ys[0]) / ys[0]) * 100, 2):>6.2f}%', end='\t')
            thread_contribution = (speed - ys[0]) / ys[0] * 100 / max(1, thr - 1)
            print(f'+{round(thread_contribution, 2):>6.2f}%')
            if thr > 1:
                overall_thread_contributions.append(thread_contribution)

        plt.plot(xs, ys,
                 color=IMPLS[impl]['color'],
                 linestyle=IMPLS[impl]['linestyle'],
                 marker=IMPLS[impl]['marker'],
                 markersize=8)

    pltlegend(plt, legend, x0=-0.18, width=1.25, ncol=2)
    plt.xlabel('Number of threads')
    plt.xticks(ticks=xs)
    plt.ylabel('Average speed [MiB/s]')
    plt.ylim(0, 1800)
    plt.savefig(f'graphs/keymix-f{fanout}-threading-speed.pdf', bbox_inches='tight', pad_inches=0)
    plt.close()

print('-------------- Overall')
print('Additional thread improvement', end='\t')
print(f'+{statistics.mean(overall_thread_contributions):>6.2f} (avg)', end='\t')
print(f'+{statistics.median(overall_thread_contributions):>6.2f} (median)')
