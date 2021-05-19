from matplotlib import pyplot as plt
import numpy as np


def print_latex_table(years, cves):
    print("\\begin{tabular}[width=\\linewidth]{ll}")
    print("\\hline")
    print("Year & Total CVE's \\")
    print("\\hline")
    for i in range(len(years)):
        print("{} & \\multicolumn{{1}}{{c}}{{{}}} \\\\".format(years[i], len(cves[i])))
    print("\\hline")
    print("\\end{tabular}")


def print_latex_table_big(years, classfreq_per_year):
    print("\\begin{tabular}[width=\\linewidth]{llllllllllll}")
    print("\\hline")
    print("Class", end="")
    for y in years:
        print("& {} ".format(y), end="")
    print("\\\\")
    print("\\hline")
    for classification, freq_per_year in classfreq_per_year.items():
        print("\\multicolumn{{1}}{{l|}}{{{}}} ".format(classification.replace("_", " ")), end="")
        for i in freq_per_year:
            print("& {} ".format(i), end="")
        print("\\\\")
    print("\\end{tabular}")


def plot_bargraph(years, classfreq_per_year, name):
    x = np.arange(len(years))  # the label locations
    width = 0.05  # the width of the bars
    off = len(classfreq_per_year.keys())/2 * width
    colors = ["blue", "orange", "brown", "red", "purple", "green", "pink",
              "gray", "olive", "black", "gold", "darkviolet", "royalblue"]

    fig, ax = plt.subplots()
    i = 0
    for classification, freq_per_year in classfreq_per_year.items():
        ax.bar(x-off+(i*width), freq_per_year, width, label=classification.replace("_", " "), facecolor=colors[i])
        i += 1

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel('Amount of times a vulnerability class has been registered')
    ax.set_xlabel('Year wherein the CVE was registered')
    ax.set_xticks(x)
    ax.set_xticklabels(years)
    ax.legend()
    fig.tight_layout()

    plt.savefig(name)
    # plt.show()


def plot_linegraph(years, classfreq_per_year, name):
    fig, ax = plt.subplots()
    for classification, freq_per_year in classfreq_per_year.items():
        ax.plot(years[:-1], freq_per_year[:-1], label=classification.replace("_", " "))

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel('Amount of times a vulnerability class has been registered')
    ax.set_xlabel('Year wherein the CVE was registered')
    ax.set_xticks(years[:-1])
    ax.set_yticks([x for x in range(0, 90, 10)])
    ax.legend()

    plt.savefig(name)
    # plt.show()
