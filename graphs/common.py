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

def pltlegend(plt, handles, labels, x0=0, width=1, is_with_legend=True, ncol=3):
    if not is_with_legend:
        return

    # Remove errorbar
    handles = [h[0] if isinstance(h, container.ErrorbarContainer) else h for h in handles]

    y0 = 1.02
    height = 0.2
    legend = plt.legend(handles, labels,
                        frameon=False,
                        mode='expand',
                        bbox_to_anchor=(x0, y0, width, height),
                        ncol=ncol,
                        handlelength=1.5,
                        loc='lower left')
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
