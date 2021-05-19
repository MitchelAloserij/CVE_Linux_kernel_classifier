import ijson
import datetime
from cwe_classifier import classify_on_cwe, manual_cve_classifiers


# This function extracts a list of CPE strings that are vulnerable for this specific CVE
def extract_cpes(nodes, cpe_list):
    for node in nodes:
        if "children" in node:
            extract_cpes(node['children'], cpe_list)
        else:
            for cpe_match in node['cpe_match']:
                if cpe_match['vulnerable']:
                    cpe_list += [cpe_match['cpe23Uri']]


# This function extracts a list of CWE ids that are attached to the CVE
def extract_cwes(types, cwe_list):
    for cwe in types['problemtype_data']:
        for cwe_lang in cwe['description']:
            if cwe_lang['lang'] == "en":
                cwe_list += [cwe_lang['value']]


# This function safely extracts the baseMetricV3 base score
# if an error occurs, it returns -1
def extract_score(impact):
    if 'baseMetricV3' in impact:
        if 'cvssV3' in impact['baseMetricV3']:
            return float(impact['baseMetricV3']['cvssV3']['baseScore'])
    return float(-1)


# This function checks the array of CPEs if it contains a linux kernel reference
def find_linux_kernel_cpe(cpes):
    for cpe in cpes:
        if "linux:linux_kernel" in cpe:
            return 1
    return 0


# This function counts the frequence of every CVE classification for a specific year
def count_cwe_occurances(cves):
    found_classes = {}
    for cve in cves:
        c = cve["class"]
        if c not in found_classes:
            found_classes[c] = 1
        else:
            found_classes[c] += 1
    return found_classes


cnt = 0


# This function parses a CVE data file into an array of CVE dictionaries
# Within every dictionary is the usefull data for one specific CVE that has a
# relation with the linux kernel
def cve_parser(year, path):
    f = open(path)
    cves = []
    disputed_ctr = 0
    evaluated_cves = 0
    discarded_noinfo = 0

    for o in ijson.items(f, 'CVE_Items.item'):
        evaluated_cves += 1

        # Extract list of vulnerable platforms
        cpe_list = []
        extract_cpes(o['configurations']['nodes'], cpe_list)

        # Check if this CVE targets the linux kernel platform
        # If not, then it ignores the CVE
        if not find_linux_kernel_cpe(cpe_list):
            continue

        # Extract the id, publish date, impact score and description
        cve_id = o['cve']['CVE_data_meta']['ID']
        cve_date = datetime.datetime.strptime(o['publishedDate'][0:10], '%Y-%m-%d')
        cve_score = extract_score(o['impact'])
        cve_descr = ""
        for d in o['cve']['description']['description_data']:
            if d['lang'] == "en":
                cve_descr = d['value']
                break

        # Check if the CVE isn't disputed, if it is, then ignore it
        if "** DISPUTED **" in cve_descr:
            disputed_ctr += 1
            continue

        # Extract the list of weaknesses this vulnerability exploits
        cwe_list = []
        if cve_id in manual_cve_classifiers:
            cwe_list = ["manual"]
        else:
            extract_cwes(o['cve']['problemtype'], cwe_list)

        # Check if the CWE class isn't 'noinfo', if it is, then ignore it due to lack of information about the CVE
        if len(cwe_list) == 1 and "NVD-CWE-noinfo" in cwe_list:
            discarded_noinfo += 1
            continue

        if "double fetch" in cve_descr:
            global cnt
            cnt += 1
            print(cve_id, cve_descr, cwe_list)

        # Classify the CVE
        classification = classify_on_cwe(cve_id, cwe_list)

        # Store results
        cves += [{
            "id": cve_id,
            "date": cve_date,
            "score": cve_score,
            "descr": cve_descr,
            "cwes": cwe_list,
            "cpes": cpe_list,
            "class": classification
        }]

    # Cleanup and return found cves
    f.close()
    print("[{}] Evaluated: {}\tLinux kernel CVE: {}\tDisputed: {}\tDiscarded NoInfo: {}".format(year,
                                                                                                evaluated_cves,
                                                                                                len(cves),
                                                                                                disputed_ctr,
                                                                                                discarded_noinfo))

    print(cnt)
    return cves
