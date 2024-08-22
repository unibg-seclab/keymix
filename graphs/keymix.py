import statistics
from itertools import product

import matplotlib.pyplot as plt
import pandas as pd

from common import *

FILE = 'data/out-aqua.csv'

df = pd.read_csv(FILE)

implementations = sorted(df.implementation.unique())
impl_legend= ['AES-NI', 'OpenSSL', 'wolfSSL']
markers = ['o', '^', 's']
linestyles = ['solid', 'dashed', 'dotted']
fanouts = list(df.fanout.unique())

# ---------------------------------------------------------- Basic keymix graphs

for fanout in fanouts:
    match fanout:
        case 2:
            threads = [1]
        case 3:
            threads = [1]
        case 4:
            threads = [1]

    legend = [f'{impl}' if thr == 1 else f'{impl} ({thr} threads)' for thr, impl in product(threads, impl_legend)]

    # --------------------------- Time

    plt.figure()
    # plt.title(f'Keymix time (fanout {fanout})')

    for style, t in zip(linestyles, threads):
        for m, impl in zip(markers, implementations):
            data = df_filter(df, impl, fanout)
            data = data[data.internal_threads == t]
            data = df_groupby(data, 'key_size')
            xs = [to_mib(x) for x in data.key_size]
            ys = [to_sec(y) for y in data.time_mean]
            plt.loglog(xs, ys, linestyle=style, marker=m, markersize=8)

    pltlegend(plt, legend, x0=-0.1, width=1.2)
    plt.xlabel('Key size [MiB]')
    plt.ylabel('Average time [s]')
    plt.ylim(1e-2, 1e3)
    plt.savefig(f'graphs/keymix-f{fanout}-time.pdf', bbox_inches='tight', pad_inches=0)
    plt.close()

    # --------------------------- speed

    plt.figure()
    # plt.title(f'Keymix speed (fanout {fanout})')

    for style, t in zip(linestyles, threads):
        for m, impl in zip(markers, implementations):
            data = df_filter(df, impl, fanout)
            data = data[data.internal_threads == t]
            data = df_groupby(data, 'key_size')
            xs = [to_mib(x) for x in data.key_size]
            ys = [x / to_sec(y) for x, y in zip(xs, data.time_mean)]
            plt.loglog(xs, ys, linestyle=style, marker=m, markersize=8)

    pltlegend(plt, legend, x0=-0.1, width=1.2)
    plt.xlabel('Key size [MiB]')
    plt.ylabel('Average speed [MiB/s]')
    plt.ylim(1e1, 1e3)
    plt.savefig(f'graphs/keymix-f{fanout}-speed.pdf', bbox_inches='tight', pad_inches=0)
    plt.close()

# ---------------------------------------------------------- Threading improvements

overall_thread_contributions = []

for fanout in fanouts:
    # Select 1st key sizes >100MiB for the given fanout
    match fanout:
        case 2: size = 201326592 # 192MiB
        case 3: size = 229582512 # 218.95MiB
        case 4: size = 201326592 # 192MiB

    plt.figure()
    # plt.title(f'Improvements for size {round(to_mib(size) / 1024, 2)} GiB (fanout {fanout})')
    for m, impl in zip(markers, implementations):
        data = df_filter(df, impl, fanout)
        data = data[data.key_size == size]
        data = df_groupby(data, 'internal_threads')
        xs = list(data.internal_threads)
        ys = [to_sec(y) for y in data.time_mean]

        plt.plot(xs, ys, marker=m, markersize=8)

    pltlegend(plt, impl_legend, x0=-0.1, width=1.2)
    plt.xlabel('Number of threads')
    plt.xticks(ticks=xs)
    plt.ylabel('Average time [s]')
    plt.ylim(0, 5.2)
    plt.savefig(f'graphs/keymix-f{fanout}-threading-time.pdf', bbox_inches='tight', pad_inches=0)
    plt.close()

    print('-------------- Fanout', fanout)
    plt.figure()
    # plt.title(f'Improvements for size {round(to_mib(size) / 1024, 2)} GiB (fanout {fanout})')
    for m, impl in zip(markers, implementations):
        data = df_filter(df, impl, fanout)
        data = data[data.key_size == size]
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

        plt.plot(xs, ys, marker=m, markersize=8)

    pltlegend(plt, impl_legend, x0=-0.1, width=1.2)
    plt.xlabel('Number of threads')
    plt.xticks(ticks=xs)
    plt.ylabel('Average speed [MiB/s]')
    plt.ylim(0, 1200)
    plt.savefig(f'graphs/keymix-f{fanout}-threading-speed.pdf', bbox_inches='tight', pad_inches=0)
    plt.close()

print('-------------- Overall')
print('Additional thread improvement', end='\t')
print(f'+{statistics.mean(overall_thread_contributions):>6.2f} (avg)', end='\t')
print(f'+{statistics.median(overall_thread_contributions):>6.2f} (median)')
