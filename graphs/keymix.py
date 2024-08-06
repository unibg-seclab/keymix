import matplotlib.pyplot as plt
import pandas as pd

from itertools import product

from common import *

FILE = 'data/out-preliminary.csv'

df = pd.read_csv(FILE)

implementations = ['openssl', 'wolfssl']
impl_legend= ['OpenSSL', 'wolfSSL']
markers = ['*', 'o']
linestyles = ['solid', 'dashed', 'dotted']
fanouts = list(df.fanout.unique())

def derive_data(df, impl, fanout, threads):
    data = df[(df.implementation == impl) & (df.fanout == fanout) & (df.internal_threads == threads)]
    data = data.groupby('key_size', as_index=False).agg({'time': ['mean', 'std']})
    data.columns = ['key_size', 'time_mean', 'time_std']
    data.reindex(columns=data.columns)
    return data

# ---------------------------------------------------------- Basic keymix graphs

for fanout in fanouts:
    match fanout:
        case 2:
            threads = [1, 2, 4]
        case 3:
            threads = [1, 3]
        case 4:
            threads = [1, 4]

    legend = [f'{impl}' if thr == 1 else f'{impl} ({thr} threads)' for thr, impl in product(threads, impl_legend)]

    # --------------------------- Time

    plt.figure()
    # plt.title(f'Keymix time (fanout {fanout})')

    for style, t in zip(linestyles, threads):
        for m, impl in zip(markers, implementations):
            data = derive_data(df, impl, fanout, t)
            xs = [to_mib(x) for x in data.key_size]
            ys = [to_sec(y) for y in data.time_mean]
            plt.loglog(xs, ys, marker=m, linestyle=style)

    pltlegend(plt, legend)
    plt.xlabel('Key size [MiB]')
    plt.ylabel('Average time [s]')
    plt.ylim(1e-2, 1e3)
    plt.savefig(f'graphs/keymix-f{fanout}-time.pdf', bbox_inches='tight')

    # --------------------------- speed

    plt.figure()
    # plt.title(f'Keymix speed (fanout {fanout})')

    for style, t in zip(linestyles, threads):
        for m, impl in zip(markers, implementations):
            data = derive_data(df, impl, fanout, t)
            xs = [to_mib(x) for x in data.key_size]
            ys = [x / to_sec(y) for x, y in zip(xs, data.time_mean)]
            plt.loglog(xs, ys, marker=m, linestyle=style)

    pltlegend(plt, legend)
    plt.xlabel('Key size [MiB]')
    plt.ylabel('Average speed [MiB/s]')
    plt.ylim(1e1, 1e3)
    plt.savefig(f'graphs/keymix-f{fanout}-speed.pdf', bbox_inches='tight')

# ---------------------------------------------------------- Threading improvements

def derive_data_threads(df, fanout, impl, size):
        data = df[(df.fanout == fanout) & (df.implementation == impl) & (df.key_size == size)]
        data = data.groupby('internal_threads', as_index=False).agg({'time': ['mean', 'std']})
        data.columns = ['internal_threads', 'time_mean', 'time_std']
        data.reindex(columns=data.columns)
        return data
    

for fanout in fanouts:
    match fanout:
        case 2: size = 3221225472
        case 3: size = 2066242608
        case 4: size = 3221225472

    plt.figure()
    # plt.title(f'Improvements for size {round(to_mib(size) / 1024, 2)} GiB (fanout {fanout})')
    for m, impl in zip(markers, implementations):
        data = derive_data_threads(df, fanout, impl, size)
        xs = list(data.internal_threads)
        ys = [to_sec(y) for y in data.time_mean]

        plt.plot(xs, ys, marker=m)

    pltlegend(plt, impl_legend, cols=2)
    plt.xlabel('Number of threads')
    plt.ylabel('Average time [s]')
    plt.ylim(0, 140)
    plt.xscale('log')
    plt.savefig(f'graphs/keymix-f{fanout}-threading-time.pdf', bbox_inches='tight')

    plt.figure()
    # plt.title(f'Improvements for size {round(to_mib(size) / 1024, 2)} GiB (fanout {fanout})')
    for m, impl in zip(markers, implementations):
        data = derive_data_threads(df, fanout, impl, size)
        xs = list(data.internal_threads)
        ys = [to_mib(size) / to_sec(y) for y in data.time_mean]

        plt.plot(xs, ys, marker=m)

    pltlegend(plt, impl_legend, cols=2)
    plt.xlabel('Number of threads')
    plt.ylabel('Average speed [MiB/s]')
    plt.ylim(0, 250)
    plt.xscale('log')
    plt.savefig(f'graphs/keymix-f{fanout}-threading-speed.pdf', bbox_inches='tight')
