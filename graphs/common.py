import matplotlib

matplotlib.rc('font', size=12)
matplotlib.rc('pdf', fonttype=42)

def to_mib(bytes):
    return bytes / 1024 / 1024

def to_sec(ms):
    return ms / 1000

def pltlegend(plt, labels, ncol=2):
    x0, y0 = 0, 1.02
    width = 1
    height = 0.2
    plt.legend(labels,
               frameon=False,
               mode='expand',
               bbox_to_anchor=(x0, y0, width, height),
               ncol=ncol,
               handlelength=1,
               loc="lower left")
