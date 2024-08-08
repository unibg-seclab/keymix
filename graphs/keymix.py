import matplotlib.pyplot as plt
import pandas as pd

from itertools import product

from common import *

FILE = 'data/out.csv'

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
            plt.loglog(xs, ys, marker=m, linestyle=style)

    pltlegend(plt, legend)
    plt.xlabel('Key size [MiB]')
    plt.ylabel('Average time [s]')
    plt.ylim(1e-2, 1e3)
    plt.savefig(f'graphs/keymix-f{fanout}-time.pdf', bbox_inches='tight')
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
            plt.loglog(xs, ys, marker=m, linestyle=style)

    pltlegend(plt, legend)
    plt.xlabel('Key size [MiB]')
    plt.ylabel('Average speed [MiB/s]')
    plt.ylim(1e1, 1e3)
    plt.savefig(f'graphs/keymix-f{fanout}-speed.pdf', bbox_inches='tight')
    plt.close()

# ---------------------------------------------------------- Threading improvements

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

        plt.plot(xs, ys, marker=m)

    pltlegend(plt, impl_legend)
    plt.xlabel('Number of threads')
    plt.xticks(ticks=xs)
    plt.ylabel('Average time [s]')
    plt.ylim(0, 10)
    plt.savefig(f'graphs/keymix-f{fanout}-threading-time.pdf', bbox_inches='tight')
    plt.close()

    plt.figure()
    # plt.title(f'Improvements for size {round(to_mib(size) / 1024, 2)} GiB (fanout {fanout})')
    for m, impl in zip(markers, implementations):
        data = df_filter(df, impl, fanout)
        data = data[data.key_size == size]
        data = df_groupby(data, 'internal_threads')
        xs = list(data.internal_threads)
        ys = [to_mib(size) / to_sec(y) for y in data.time_mean]

        plt.plot(xs, ys, marker=m)

    pltlegend(plt, impl_legend)
    plt.xlabel('Number of threads')
    plt.xticks(ticks=xs)
    plt.ylabel('Average speed [MiB/s]')
    plt.ylim(0, 550)
    plt.savefig(f'graphs/keymix-f{fanout}-threading-speed.pdf', bbox_inches='tight')
    plt.close()
