import statistics

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from common import *

FILE = 'data/enc-aqua.csv'

df = pd.read_csv(FILE)
df['outsize_mib'] = to_mib(df.outsize)


keep_files_mib = [1, 10, 100, 1024, 10240, 102400]
df = df[df.outsize_mib.isin(keep_files_mib)]

# implementations = ['aesni', 'openssl', 'wolfssl']
# impl_legend= ['AES-NI', 'OpenSSL', 'wolfSSL']
# fanouts = [2, 3, 4]
impl = 'aesni'
impl_legend = 'AES-NI'
fanout = 3
ithr = 3

markers = ["o", "s", "^", "D", "*", "p", "h", "8", "v"]

df = df[(df.fanout == fanout) & (df.internal_threads == ithr) & (df.implementation == impl)]

# ----------------------------------------- "Traditional" encryption curves

data = df[df.external_threads == 1]
key_sizes = sorted(data.key_size.unique())
key_sizes_in_mib = [to_mib(k) for k in key_sizes]

plt.figure()
# plt.title(f'Encryption times, {name} (fanout {fanout})')
for i, size in enumerate(key_sizes):
    grouped = df_groupby(data[data.key_size == size], 'outsize')
    xs = [to_mib(x) for x in grouped.outsize]
    ys = [to_sec(y) for y in grouped.time_mean]
    plt.plot(xs, ys, marker=markers[i], markersize=8)

plt.xscale('log')
plt.yscale('log')
pltlegend(plt,
          [f'{int(k)} MiB' if k == int(k) else f'{round(k, 2)} MiB' for k in key_sizes_in_mib],
          x0=-0.155,
          width=1.3)
plt.xlabel('File size [MiB]')
plt.ylabel('Average time [s]')
plt.savefig(f'graphs/enc-f{fanout}-{impl}-time.pdf', bbox_inches='tight', pad_inches=0)
plt.close()

max_speed = 0

plt.figure()
# plt.title(f'Encryption speeds, {name} (fanout {fanout})')
for i, size in enumerate(key_sizes):
    grouped = df_groupby(data[data.key_size == size], 'outsize')
    xs = [to_mib(x) for x in grouped.outsize]
    ys = [x / to_sec(y) for x, y in zip(xs, grouped.time_mean)]
    max_speed = max([max_speed] + ys)
    plt.plot(xs, ys, marker=markers[i], markersize=8)

plt.xscale('log')
plt.yscale('log')
pltlegend(plt,
          [f'{int(k)} MiB' if k == int(k) else f'{round(k, 2)} MiB' for k in key_sizes_in_mib],
          x0=-0.155,
          width=1.3)
plt.xlabel('File size [MiB]')
plt.ylabel('Average speed [MiB/s]')
plt.savefig(f'graphs/enc-f{fanout}-{impl}-speed.pdf', bbox_inches='tight', pad_inches=0)
plt.close()

print('--- Single-core encryption speeds')
print(f"Max speed = {max_speed} [MiB/s]")

# # ----------------------------------------- Multi-threading improvements


# outsize = 1073741824 # 1GiB
# outsize = 10737418240 # 10GiB
outsize = 107374182400 # 100GiB
# Select 1st three key sizes >100MiB for the given fanout
# sizes = [229582512, 688747536, 2066242608]

key_sizes_in_mib = [to_mib(k) for k in key_sizes]
data = df[df.outsize == outsize]

plt.figure()
for i, size in enumerate(key_sizes):
    grouped = df_groupby(data[data.key_size == size], 'external_threads')
    xs = list(grouped.external_threads)
    ys = [to_sec(y) for y in grouped.time_mean]
    plt.plot(xs, ys, marker=markers[i], markersize=8)

pltlegend(plt,
          [f'{int(k)} MiB' if k == int(k) else f'{round(k, 2)} MiB' for k in key_sizes_in_mib],
          x0=-0.155,
          width=1.3)
plt.xlabel('Number of concurrent blocks')
plt.ylabel('Average time [s]')
plt.savefig(f'graphs/enc-f{fanout}-{impl}-threading-time.pdf', bbox_inches='tight', pad_inches=0)
plt.close()

print('\n--- Multi-core encryption speeds')
thread_contributions = [[] for i in range(len(xs))]

plt.figure()
for i, size in enumerate(key_sizes):
    grouped = df_groupby(data[data.key_size == size], 'external_threads')
    xs = list(grouped.external_threads)
    ys = [to_mib(outsize) / to_sec(y) for y in grouped.time_mean]
    plt.plot(xs, ys, marker=markers[i], markersize=8)

    print('=== For size', to_mib(size))
    for thr, speed in zip(xs, ys):
            print('Threads =', thr, end='\t')
            print('Speed   =', speed, end='\t')
            print(f'+{round(((speed - ys[0]) / ys[0]) * 100, 2):>6.2f}%', end='\t')
            thread_contribution = (speed - ys[0]) / ys[0] * 100 / max(1, thr - 1)
            print(f'+{round(thread_contribution):>3}%')
            thread_contributions[thr - 1].append(thread_contribution)
    
print('=== Overall')
for thr, contribs in enumerate(thread_contributions):
    print('Threads =', thr + 1, end='\t')
    print(f'+{round(statistics.mean(contribs)):>3}% (avg)', end='\t')
    print(f'+{round(statistics.median(contribs)):>3}% (median)')


pltlegend(plt,
          [f'{int(k)} MiB' if k == int(k) else f'{round(k, 2)} MiB' for k in key_sizes_in_mib],
          x0=-0.155,
          width=1.3)
plt.xticks(xs)
plt.xlabel('Number of concurrent blocks')
plt.ylabel('Average speed [MiB/s]')
plt.savefig(f'graphs/enc-f{fanout}-{impl}-threading-speed.pdf', bbox_inches='tight', pad_inches=0)
plt.close()
