import matplotlib

matplotlib.rc('font', size=12)
matplotlib.rc('pdf', fonttype=42)

def to_mib(bytes):
    return bytes / 1024 / 1024

def to_sec(ms):
    return ms / 1000

def pltlegend(plt, labels, cols=None):
    columns = cols if cols is not None else len(labels) // 2
    if columns < 3:
        x0, y0 = 0.1, 1.02
        width = 0.8
    else:
        x0, y0 = -0.14, 1.02
        width = 1.17
    height = 0.2
    plt.legend(labels,
               frameon=False,
               mode='expand',
               bbox_to_anchor=(x0, y0, width, height),
               ncol=columns,
               handlelength=1.5,
               loc="lower left")

def df_filter(df, impl, fanout):
    return df[(df.implementation == impl) & (df.fanout == fanout)]

def df_groupby(df, colname):
    data = df.groupby(colname, as_index=False).agg({'time': ['mean', 'std']})
    data.columns = [colname, 'time_mean', 'time_std']
    data.reindex(columns=data.columns)
    return data
