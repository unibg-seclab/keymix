import matplotlib
from matplotlib import container

matplotlib.rc('font', size=18, family=['NewComputerModern08', 'sans-serif'])
matplotlib.rc('pdf', fonttype=42)

def to_mib(bytes):
    return bytes / 1024 / 1024

def to_gib(bytes):
    return bytes / 1024 / 1024 / 1024

def to_sec(ms):
    return ms / 1000

def export_legend(legend, filename):
    fig = legend.figure
    fig.canvas.draw()
    bbox = legend.get_window_extent().transformed(fig.dpi_scale_trans.inverted())
    fig.savefig(filename, dpi='figure', bbox_inches=bbox)

def pltlegend(plt, handles, labels, x0=0, width=1, ncol=3, inside=True, expand=True, loc='best',
              to_sort=False, title=None):
    mode = 'expand' if expand else None

    # Remove errorbar
    handles = [h[0] if isinstance(h, container.ErrorbarContainer) else h for h in handles]

    if to_sort:
        # Sort both labels and handles by labels
        labels, handles = zip(*sorted(zip(labels, handles), key=lambda t: t[0]))

    if inside:
        legend = plt.legend(handles, labels, handlelength=1, mode=mode, ncol=ncol, loc=loc,
                            title=title)
    else:
        y0 = 1.02
        height = 0.2
        legend = plt.legend(handles, labels, bbox_to_anchor=(x0, y0, width, height), frameon=False,
                            handlelength=1, loc='lower left', mode=mode, ncol=ncol, title=title)

    return legend

def df_filter(df, impl, fanout):
    return df[(df.implementation == impl) & (df.fanout == fanout)]

def df_groupby(df, cols, agg='time'):
    data = df.groupby(cols, as_index=False).agg({agg: ['mean', 'std']})
    if type(cols) == list:
        data.columns = cols + [f'{agg}_mean', f'{agg}_std']
    else:
        data.columns = [cols, f'{agg}_mean', f'{agg}_std']
    data.reindex(columns=data.columns)
    return data
