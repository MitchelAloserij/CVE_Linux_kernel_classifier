from cwe_classifier import cwe_classifications
from cve_parser import cve_parser, count_cwe_occurances
from gen_output import print_latex_table, print_latex_table_big
from gen_output import plot_bargraph, plot_linegraph

# Path to directory containing all the CVE data files
source_folder = "./sources"

# Format string used to name the CVE data files, first variable is year of data file
filename_format = "nvdcve-1.1-{}.json"

# Array of years that need to be evaluated
years = [2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020]


# This function prints a table which shows amount of CVE's per classification
# for each year within the console
def print_result_table(years, classfreq_per_year):
    # Print year header
    print(" " * 26, end='')
    for y in years:
        print(y, end='\t')
    print("")

    # Print frequencies
    for classification, freq_per_year in classfreq_per_year.items():
        print(classification, ' ' * (25-len(classification)), end="")
        for f in freq_per_year:
            print(f, end="\t")
        print()


def main():
    cves = []
    found_cwes = []

    # Loop over all the year data files
    for y in years:
        filename = "{}/{}".format(source_folder, filename_format.format(y))
        # Parse all the CVE's within that year, removing the irrelevant ones
        cves += [cve_parser(y, filename)]
        # Extract all the CWE's
        found_cwes += [count_cwe_occurances(cves[-1])]

    # Convert the data to an array of frequency that a specific classification happened over the years
    classfreq_per_year = {}
    for key in cwe_classifications.keys():
        classfreq_per_year[key] = [x[key] if key in x else 0 for x in found_cwes]

    # Merge certain classes into 'other' because they didnt prove significant
    for i in range(len(years)):
        classfreq_per_year['other'][i] += classfreq_per_year['incorrect_error_handling'][i]
        classfreq_per_year['other'][i] += classfreq_per_year['incorrect_code'][i]
        classfreq_per_year['other'][i] += classfreq_per_year['infinite_loop'][i]
    del classfreq_per_year['incorrect_error_handling']
    del classfreq_per_year['incorrect_code']
    del classfreq_per_year['infinite_loop']

    # Print the results in a structured table format in the console
    print_result_table(years, classfreq_per_year)

    # Print a LaTeX table which shows the total amount of CVE's for each year
    print_latex_table(years, cves)

    # Print a LaTeX table which shows the amount of CVEs for every class for each year
    print_latex_table_big(years, classfreq_per_year)

    # Plot the bargraph of the big latex table data
    plot_bargraph(years, classfreq_per_year, "./bargraph_total.png")

    # Remove the unnecessary classes for the next graph
    del classfreq_per_year['type_error']
    del classfreq_per_year['race_condition']
    del classfreq_per_year['div_by_zero']
    del classfreq_per_year['resources_misuse']
    del classfreq_per_year['permission_error']
    del classfreq_per_year['null_ptr_dereference']
    del classfreq_per_year['other']

    # Plot the linegraph
    plot_linegraph(years, classfreq_per_year, "./linegraph_limited.png")


if __name__ == "__main__":
    main()
