import matplotlib.pyplot as plt
import pandas as pd

from common import *

FILE = 'data/out-preliminary.csv'

df = pd.read_csv(FILE)

implementations = ['openssl', 'wolfssl']
impl_legend= ['OpenSSL', 'wolfSSL']
markers = ['*', 'o', 'x']
linestyles = ['solid', 'dashed', 'dotted']
fanouts = list(df.fanout.unique())

def derive_data(df, impl, fanout, threads):
    data = df[(df.implementation == impl) & (df.fanout == fanout) & (df.internal_threads == threads)]
    data = data.groupby('key_size', as_index=False).agg({'time': ['mean', 'std']})
    data.columns = ['key_size', 'time_mean', 'time_std']
    data.reindex(columns=data.columns)
    return data

for fanout in fanouts:
    match fanout:
        case 2:
            threads = [1, 2, 4]
        case 3:
            threads = [1, 3]
        case 4:
            threads = [1, 4]

    legend = []
    for impl in impl_legend:
        for t in threads:
            entry = impl if t == 1 else f'{impl} ({t} threads)'
            legend.append(entry)

    # --------------------------- Time

    plt.figure()
    # plt.title(f'Keymix time (fanout {fanout})')

    for m, impl in zip(markers, implementations):
        for t, style in zip(threads, linestyles):
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

    for m, impl in zip(markers, implementations):
        for t, style in zip(threads, linestyles):
            data = derive_data(df, impl, fanout, t)
            xs = [to_mib(x) for x in data.key_size]
            ys = [x / to_sec(y) for x, y in zip(xs, data.time_mean)]
            plt.loglog(xs, ys, marker=m, linestyle=style)


    pltlegend(plt, legend)
    plt.xlabel('Key size [MiB]')
    plt.ylabel('Average speed [MiB/s]')
    plt.ylim(1e1, 1e3)
    plt.savefig(f'graphs/keymix-f{fanout}-speed.pdf', bbox_inches='tight')
