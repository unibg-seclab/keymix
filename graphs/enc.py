import matplotlib.pyplot as plt
import pandas as pd

from itertools import product
from matplotlib.ticker import MaxNLocator

from common import *

FILE = 'data/enc.csv'

df = pd.read_csv(FILE)

implementations = ['openssl', 'wolfssl']
impl_legend= ['OpenSSL', 'wolfSSL']
fanouts = list(df.fanout.unique())

if 'aesni' in implementations:
    ytop_speed = 2000
else:
    ytop_speed = 1100

for impl, name in zip(implementations, impl_legend):
    for fanout in fanouts:
        match fanout:
            case 2: threads = 8
            case 3: threads = 9
            case 4: threads = 4

        plt.figure()
        plt.title(f'Encryption times, {name} (fanout {fanout})')

        data = df[(df.fanout == fanout) & (df.internal_threads == threads) & (df.external_threads == 8)]
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
        plt.title(f'Encryption speeds, {name} (fanout {fanout})')

        data = df[(df.fanout == fanout) & (df.internal_threads == threads) & (df.external_threads == 8)]
        data = data[data.implementation == impl]

        key_sizes = data.key_size.unique()

        for size in key_sizes:
            grouped = df_groupby(data[data.key_size == size], 'outsize')
            xs = [to_mib(x) for x in grouped.outsize]
            ys = [x / to_sec(y) for x, y in zip(xs, grouped.time_mean)]
            plt.plot(xs, ys, marker='o')

        plt.xscale('log')
        plt.ylim(top=ytop_speed)
        plt.legend([f'{round(to_mib(k), 2)} MiB' for k in key_sizes])
        plt.xlabel('File size [MiB]')
        plt.ylabel('Average speed [MiB/s]')
        plt.savefig(f'graphs/enc-f{fanout}-{impl}-speed.pdf')
