import matplotlib.pyplot as plt
import pandas as pd

from common import *

FILE = 'data/out.csv'

df = pd.read_csv(FILE)

df['expansion'] = df.outsize / df.key_size

implementations = list(df.implementation.unique())
markers = ['*', 'o', 'x']
fanouts = list(df.fanout.unique())

is_ethr = lambda x: df.external_threads == x
is_ithr = lambda x: df.internal_threads == x
is_single_threaded = is_ithr(1) & is_ethr(1)
is_exp1 = df.expansion == 1

################################################################# Encryption of 1 key, single threaded vs 2 thread

for fanout in fanouts:
    plt.figure()
    plt.title(f'Encryption time of 1 key (with fanout {fanout})')

    for marker, impl in zip(markers, implementations):
            data = df[(df.implementation == impl) & (df.fanout == fanout) & is_exp1 & is_single_threaded]
            data = data.groupby('key_size', as_index=False).agg({'time': ['mean', 'std']})
            data.columns = ['key_size', 'time_mean', 'time_std']
            data.reindex(columns=data.columns)
            xs = [to_mib(x) for x in data.key_size]
            ys = [to_sec(y) for y in data.time_mean]
            plt.plot(xs, ys, marker=marker)

    thr = 2
    for marker, impl in zip(markers, implementations):
            data = df[(df.implementation == impl) & (df.fanout == fanout) & is_exp1 & is_ithr(thr) & is_ethr(1)]
            data = data.groupby('key_size', as_index=False).agg({'time': ['mean', 'std']})
            data.columns = ['key_size', 'time_mean', 'time_std']
            data.reindex(columns=data.columns)
            xs = [to_mib(x) for x in data.key_size]
            ys = [to_sec(y) for y in data.time_mean]
            plt.plot(xs, ys, marker=marker, linestyle='dashed')

    plt.legend(implementations + [f'{impl} ({thr})' for impl in implementations])
    plt.xlabel('Key size [MiB]')
    plt.ylabel('Average time [s]')
    plt.xscale('log')
    plt.savefig(f'graphs/by-fanout-{fanout}-time.pdf')

    plt.figure()
    plt.title(f'Encryption speed of 1 key (with fanout {fanout})')

    for marker, impl in zip(markers, implementations):
            data = df[(df.implementation == impl) & (df.fanout == fanout) & is_exp1 & is_single_threaded]
            data = data.groupby('key_size', as_index=False).agg({'time': ['mean', 'std']})
            data.columns = ['key_size', 'time_mean', 'time_std']
            data.reindex(columns=data.columns)
            xs = [to_mib(x) for x in data.key_size]
            ys = [x / to_sec(y) for x, y in zip(xs, data.time_mean)]
            plt.plot(xs, ys, marker=marker)

    plt.legend(implementations)
    plt.xlabel('Key size [MiB]')
    plt.ylabel('Average speed [MiB/s]')
    plt.xscale('log')
    plt.savefig(f'graphs/by-fanout-{fanout}-speed.pdf')

################################################################# Multi threaded graphs
