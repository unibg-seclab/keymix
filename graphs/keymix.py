import matplotlib.pyplot as plt
import pandas as pd

from common import *

FILE = 'data/out-preliminary.csv'

df = pd.read_csv(FILE)

implementations = list(df.implementation.unique())
markers = ['*', 'o', 'x']
fanouts = list(df.fanout.unique())

for fanout in fanouts:
    # --------------------------- Time

    plt.figure()
    plt.title(f'Keymix time (fanout {fanout})')

    for m, impl in zip(markers, implementations):
        data = df[(df.implementation == impl) & (df.fanout == fanout) & (df.internal_threads == fanout)]
        data = data.groupby('key_size', as_index=False).agg({'time': ['mean', 'std']})
        data.columns = ['key_size', 'time_mean', 'time_std']
        data.reindex(columns=data.columns)
        # print(data)

        xs = [to_mib(x) for x in data.key_size]
        ys = [to_sec(y) for y in data.time_mean]
        plt.loglog(xs, ys, marker=m)


    plt.legend(implementations)
    plt.xlabel('Key size [MiB]')
    plt.ylabel('Average time [s]')
    plt.savefig(f'graphs/by-fanout-{fanout}-time.pdf')

    # --------------------------- speed

    plt.figure()
    plt.title(f'Keymix speed (fanout {fanout})')

    for m, impl in zip(markers, implementations):
        data = df[(df.implementation == impl) & (df.fanout == fanout) & (df.internal_threads == fanout)]
        data = data.groupby('key_size', as_index=False).agg({'time': ['mean', 'std']})
        data.columns = ['key_size', 'time_mean', 'time_std']
        data.reindex(columns=data.columns)
        # print(data)

        xs = [to_mib(x) for x in data.key_size]
        ys = [x / to_sec(y) for x, y in zip(xs, data.time_mean)]
        plt.loglog(xs, ys, marker=m)


    plt.legend(implementations)
    plt.xlabel('Key size [MiB]')
    plt.ylabel('Average speed [MiB/s]')
    plt.savefig(f'graphs/by-fanout-{fanout}-speed.pdf')
