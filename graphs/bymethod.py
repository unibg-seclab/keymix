import matplotlib.pyplot as plt
import pandas as pd

FILE = 'data/out.csv'

df = pd.read_csv(FILE)

implementations = list(df.implementation.unique())
markers = ['*', 'o', 'x']
fanouts = list(df.diff_factor.unique())

for impl in implementations:
    plt.figure()
    plt.title(impl)
    for marker, fanout in zip(markers, fanouts):
            data = df[(df.implementation == impl) & (df.diff_factor == fanout)]
            data = data.groupby('seed_size', as_index=False).agg({'time': ['mean', 'std']})
            data.columns = ['seed_size', 'time_mean', 'time_std']
            data.reindex(columns=data.columns)
            xs = [x / 1024 / 1024 for x in data.seed_size]
            ys = [y / 1000 for y in data.time_mean]
            plt.loglog(xs, ys, marker=marker)
    plt.legend(fanouts)
    plt.xlabel('Seed size [MiB]')
    plt.ylabel('Average time [s]')
    plt.ylim(4e-2, 2e2)
    plt.savefig(f'graphs/by-method-{impl}-time.pdf')

    plt.figure()
    plt.title(impl)
    for marker, fanout in zip(markers, fanouts):
            data = df[(df.implementation == impl) & (df.diff_factor == fanout)]
            data = data.groupby('seed_size', as_index=False).agg({'time': ['mean', 'std']})
            data.columns = ['seed_size', 'time_mean', 'time_std']
            data.reindex(columns=data.columns)
            # print(data.seed_size, data.time_mean)
            xs = [x / 1024 / 1024 for x in data.seed_size]
            ys = [x / (y / 1000) for x, y in zip(xs, data.time_mean)]
            plt.plot(xs, ys, marker=marker)
    plt.legend(fanouts)
    plt.xlabel('Seed size [MiB]')
    plt.ylabel('Average speed [MiB/s]')
    plt.xscale('log')
    plt.ylim(0, 180)
    plt.savefig(f'graphs/by-method-{impl}-speed.pdf')
