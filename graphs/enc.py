import matplotlib.pyplot as plt
import pandas as pd

from common import *

FILE = 'data/enc.csv'

df = pd.read_csv(FILE)
df['outsize_mib'] = to_mib(df.outsize)

# Remove 5* MiB files
df = df[(df.outsize_mib != 5) & (df.outsize_mib != 50) & (df.outsize_mib != 500) & (df.outsize_mib != 5120)]

implementations = ['openssl', 'wolfssl', 'aesni']
impl_legend= ['OpenSSL', 'wolfSSL', 'AES-NI']
fanouts = list(df.fanout.unique())

# ----------------------------------------- "Traditional" encryption curves

for impl, name in zip(implementations, impl_legend):
    for fanout in fanouts:
        plt.figure()
        # plt.title(f'Encryption times, {name} (fanout {fanout})')

        data = df[(df.fanout == fanout) & (df.internal_threads == 1) & (df.external_threads == 1)]
        data = data[data.implementation == impl]

        key_sizes = data.key_size.unique()

        for size in key_sizes:
            grouped = df_groupby(data[data.key_size == size], 'outsize')
            xs = [to_mib(x) for x in grouped.outsize]
            ys = [to_sec(y) for y in grouped.time_mean]
            plt.plot(xs, ys, marker='o')

        plt.xscale('log')
        plt.ylim(top=25)
        plt.legend([f'{round(to_mib(k), 2)} MiB' for k in key_sizes])
        plt.xlabel('File size [MiB]')
        plt.ylabel('Average time [s]')
        plt.savefig(f'graphs/enc-f{fanout}-{impl}-time.pdf')

        plt.figure()
        # plt.title(f'Encryption speeds, {name} (fanout {fanout})')

        data = df[(df.fanout == fanout) & (df.internal_threads == 1) & (df.external_threads == 1)]
        data = data[data.implementation == impl]

        key_sizes = data.key_size.unique()

        for size in key_sizes:
            grouped = df_groupby(data[data.key_size == size], 'outsize')
            xs = [to_mib(x) for x in grouped.outsize]
            ys = [x / to_sec(y) for x, y in zip(xs, grouped.time_mean)]
            plt.plot(xs, ys, marker='o')

        plt.xscale('log')
        plt.legend([f'{round(to_mib(k), 2)} MiB' for k in key_sizes])
        plt.xlabel('File size [MiB]')
        plt.ylabel('Average speed [MiB/s]')
        plt.savefig(f'graphs/enc-f{fanout}-{impl}-speed.pdf')

# ----------------------------------------- Multi-threading improvements

for fanout in fanouts:
    match fanout:
        case 2: size = 201326592
        case 3: size = 229582512
        case 4: size = 201326592

    plt.figure()

    data = df[(df.fanout == fanout) & (df.internal_threads == 1) & (df.key_size == size)]

    for impl in implementations:
        grouped = df_groupby(data[data.implementation == impl], 'external_threads')
        xs = list(grouped.external_threads)
        ys = [to_mib(size) / to_sec(y) for y in grouped.time_mean]
        plt.plot(xs, ys, marker='o')

    pltlegend(plt, impl_legend)
    plt.xticks(xs)
    plt.xlabel('Number of threads')
    plt.ylabel('Average speed [MiB/s]')
    plt.ylim(0, 85)
    plt.savefig(f'graphs/enc-f{fanout}-threading-speed.pdf')
