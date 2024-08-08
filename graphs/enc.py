import matplotlib.pyplot as plt
import pandas as pd

from common import *

FILE = 'data/enc.csv'

df = pd.read_csv(FILE)
df['outsize_mib'] = to_mib(df.outsize)

# Remove 5* MiB files
df = df[(df.outsize_mib != 5) & (df.outsize_mib != 50) & (df.outsize_mib != 500) & (df.outsize_mib != 5120)]

implementations = ['aesni'] # ['aesni', 'openssl', 'wolfssl']
impl_legend= ['AES-NI'] # ['AES-NI', 'OpenSSL', 'wolfSSL']
fanouts = [3] # [2, 3, 4]

markers = ["o", "s", "^", "D", "*", "p", "h", "8", "v"]

# ----------------------------------------- "Traditional" encryption curves

for impl, name in zip(implementations, impl_legend):
    for fanout in fanouts:
        plt.figure()
        # plt.title(f'Encryption times, {name} (fanout {fanout})')

        data = df[(df.fanout == fanout) & (df.internal_threads == 1) & (df.external_threads == 1)]
        data = data[data.implementation == impl]

        key_sizes = data.key_size.unique()
        key_sizes_in_mib = [to_mib(k) for k in key_sizes]

        for i, size in enumerate(key_sizes):
            grouped = df_groupby(data[data.key_size == size], 'outsize')
            xs = [to_mib(x) for x in grouped.outsize]
            ys = [to_sec(y) for y in grouped.time_mean]
            plt.plot(xs, ys, marker=markers[i])

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

        for i, size in enumerate(key_sizes):
            grouped = df_groupby(data[data.key_size == size], 'outsize')
            xs = [to_mib(x) for x in grouped.outsize]
            ys = [x / to_sec(y) for x, y in zip(xs, grouped.time_mean)]
            plt.plot(xs, ys, marker=markers[i])

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
    # Select 1st three key sizes >100MiB for the given fanout
    match fanout:
        case 2:
            sizes = [201326592, 402653184, 805306368]
        case 3:
            sizes = [229582512, 688747536, 2066242608]
        case 4:
            sizes = [201326592, 805306368, 3221225472]

    plt.figure()

    for i, impl in enumerate(implementations):
        data = df[(df.fanout == fanout) & (df.internal_threads == 1) & (df.outsize == outsize) & (df.implementation == impl)]

        for i, size in enumerate(sizes):
            grouped = df_groupby(data[data.key_size == size], 'external_threads')
            xs = list(grouped.external_threads)
            ys = [to_sec(y) for y in grouped.time_mean]
            plt.plot(xs, ys, marker=markers[i])

        key_sizes_in_mib = [to_mib(k) for k in sizes]
        pltlegend(plt, [f'{int(k)} MiB' if k == int(k) else f'{round(k, 2)} MiB' for k in key_sizes_in_mib])
        plt.xticks(xs)
        plt.xlabel('Number of concurrent blocks')
        plt.ylabel('Average time [s]')
        plt.ylim(0, 35)
        plt.savefig(f'graphs/enc-f{fanout}-{impl}-threading-time.pdf', bbox_inches='tight')
        plt.close()

        plt.figure()

        data = df[(df.fanout == fanout) & (df.internal_threads == 1) & (df.outsize == outsize) & (df.implementation == impl)]

        for i, size in enumerate(sizes):
            grouped = df_groupby(data[data.key_size == size], 'external_threads')
            print(grouped.time_mean)
            xs = list(grouped.external_threads)
            ys = [to_mib(outsize) / to_sec(y) for y in grouped.time_mean]
            plt.plot(xs, ys, marker=markers[i])

        key_sizes_in_mib = [to_mib(k) for k in sizes]
        pltlegend(plt, [f'{int(k)} MiB' if k == int(k) else f'{round(k, 2)} MiB' for k in key_sizes_in_mib])
        plt.xticks(xs)
        plt.xlabel('Number of concurrent blocks')
        plt.ylabel('Average speed [MiB/s]')
        plt.ylim(0, 320)
        plt.savefig(f'graphs/enc-f{fanout}-{impl}-threading-speed.pdf', bbox_inches='tight')
        plt.close()
