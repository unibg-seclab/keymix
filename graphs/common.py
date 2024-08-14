import matplotlib

matplotlib.rc('font', size=18, family=['NewComputerModern08', 'sans-serif'])
matplotlib.rc('pdf', fonttype=42)

def to_mib(bytes):
    return bytes / 1024 / 1024

def to_sec(ms):
    return ms / 1000

def pltlegend(plt, labels, x0=0, width=1):
    y0 = 1.02
    height = 0.2
    legend = plt.legend(labels,
                        frameon=False,
                        mode='expand',
                        bbox_to_anchor=(x0, y0, width, height),
                        ncol=3,
                        handlelength=1.5,
                        loc="lower left")
    for handle in legend.legend_handles:
        handle.set_markersize(8)

def df_filter(df, impl, fanout):
    return df[(df.implementation == impl) & (df.fanout == fanout)]

def df_groupby(df, cols):
    data = df.groupby(cols, as_index=False).agg({'time': ['mean', 'std']})
    if type(cols) == list:
        data.columns = cols + ['time_mean', 'time_std']
    else:
        data.columns = [cols, 'time_mean', 'time_std']
    data.reindex(columns=data.columns)
    return data
