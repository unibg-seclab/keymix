import matplotlib.pyplot as plt
import pandas as pd

from common import *

FILE = 'data/enc.csv'

df = pd.read_csv(FILE)
df['outsize_mib'] = to_mib(df.outsize)

# Remove 5* MiB files
df = df[(df.outsize_mib != 5) & (df.outsize_mib != 50) & (df.outsize_mib != 500) & (df.outsize_mib != 5120)]

implementations = ['aesni']
impl_legend= ['AES-NI']
fanouts = [3]

# ----------------------------------------- "Traditional" encryption curves

for impl, name in zip(implementations, impl_legend):
    for fanout in fanouts:
        plt.figure()
        # plt.title(f'Encryption times, {name} (fanout {fanout})')

        data = df[(df.fanout == fanout) & (df.internal_threads == 1) & (df.external_threads == 1)]
        data = data[data.implementation == impl]

        key_sizes = data.key_size.unique()
        key_sizes_in_mib = [to_mib(k) for k in key_sizes]

        for size in key_sizes:
            grouped = df_groupby(data[data.key_size == size], 'outsize')
            xs = [to_mib(x) for x in grouped.outsize]
            ys = [to_sec(y) for y in grouped.time_mean]
            plt.plot(xs, ys, marker='o')

        plt.xscale('log')
        # plt.ylim(top=120)
        
        pltlegend(plt, [f'{int(k)} MiB' if k == int(k) else f'{round(k, 2)} MiB' for k in key_sizes_in_mib])
        plt.xlabel('File size [MiB]')
        plt.ylabel('Average time [s]')
        plt.savefig(f'graphs/enc-f{fanout}-{impl}-time.pdf', bbox_inches='tight')
        plt.close()

        plt.figure()
        # plt.title(f'Encryption speeds, {name} (fanout {fanout})')

        data = df[(df.fanout == fanout) & (df.internal_threads == 1) & (df.external_threads == 1)]
        data = data[data.implementation == impl]

        for size in key_sizes:
            grouped = df_groupby(data[data.key_size == size], 'outsize')
            xs = [to_mib(x) for x in grouped.outsize]
            ys = [x / to_sec(y) for x, y in zip(xs, grouped.time_mean)]
            plt.plot(xs, ys, marker='o')

        plt.xscale('log')
        # plt.ylim(top=75)
        pltlegend(plt, [f'{int(k)} MiB' if k == int(k) else f'{round(k, 2)} MiB' for k in key_sizes_in_mib])
        plt.xlabel('File size [MiB]')
        plt.ylabel('Average speed [MiB/s]')
        plt.savefig(f'graphs/enc-f{fanout}-{impl}-speed.pdf', bbox_inches='tight')
        plt.close()

# ----------------------------------------- Multi-threading improvements

for fanout in fanouts:
    outsize = 1073741824 # 1GiB
    # Select 1st key sizes >100MiB for the given fanout
    match fanout:
        case 2:
            size = 201326592 # 192MiB
        case 3:
            size = 229582512 # 218.95MiB
        case 4:
            size = 201326592 # 192MiB

    plt.figure()

    data = df[(df.fanout == fanout) & (df.internal_threads == 1) & (df.outsize == outsize) & (df.key_size == size)]

    for impl in implementations:
        grouped = df_groupby(data[data.implementation == impl], 'external_threads')
        xs = list(grouped.external_threads)
        ys = [to_mib(size) / to_sec(y) for y in grouped.time_mean]
        plt.plot(xs, ys, marker='o')

    pltlegend(plt, impl_legend)
    plt.xticks(xs)
    plt.xlabel('Number of concurrent blocks')
    plt.ylabel('Average speed [MiB/s]')
    plt.ylim(0, 85)
    plt.savefig(f'graphs/enc-f{fanout}-threading-speed.pdf', bbox_inches='tight')
    plt.close()
