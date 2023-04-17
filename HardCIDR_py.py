import gzip
import re
import subprocess
import pandas as pd
import json
from pandas import json_normalize
import shutil
import requests
import ipaddress
import netaddr
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from pathlib import Path  
from tabulate import tabulate


parser = ArgumentParser(description="BARDCidr!", formatter_class=ArgumentDefaultsHelpFormatter)
parser.add_argument("--target", action="store", help="Organization name. Organizations with multiple word names must be enclosed in double quotes!", required=True)
parser.add_argument("--output", action="store", help="Output to given filename as csv. Default is to output to the screen.")
args = parser.parse_args()

org_name = args.target
output = args.output

def cleanRIROuput(name, input, rir):
    network = {"query":[], "CIDR":[], "inetnum":[], "org":[], "netname":[], "country":[], "url":[]}
    inetnums_clean = []
    if rir == 'ripe' or rir == 'apnic' or rir == 'afrinic':
        input = str(input).replace("\\n\\n", ";")
        inetnums = re.findall(r'inetnum.[^;]*source\:\s*', input)
        for item in inetnums:
            item = item.replace("        ", "")
            item = item.replace("       ", "")
            item = item.replace('b"','')
            item = item.replace('\\n\\n\\n"', '')
            item = item.replace('\\n', ',')
            item = item.replace(',,', ',')
            item = item.replace('# Filtered,', ';')
            inetnums_clean.append(item)
        for item in inetnums_clean:
            iprange = re.findall('\d+\.\d+\.\d+\.\d+', item)
            cidr = netaddr.iprange_to_cidrs(iprange[0], iprange[1])
            cidr_clean = re.search("\'(.[^']*)\'", str(cidr))
            inetnum_temp = re.search("inetnum\:(.[^,]*),", item)
            inetnumhtml = inetnum_temp[1].replace(' ', '%20').replace('-','%2D').replace(',','%2C').replace('.','%2E').replace('&','%26')
            netname = re.search("netname\:(.[^,]*),", item)
            country = re.search("country\:(.[^,]*),", item)
            if rir == 'ripe':
                inetnumurl = "https://apps.db.ripe.net/search/lookup.html?source=ripe&key=" + inetnumhtml + "&type=inetnum"
            if rir == 'apnic':
                inetnumurl = "http://wq.apnic.net/apnic-bin/whois.pl?searchtext=" + inetnumhtml
            if rir == 'afrinic':
                inetnumurl = "http://www.afrinic.net/en/services/whois-query"
            network["query"].append(name)
            network["CIDR"].append(cidr_clean[1])
            network["inetnum"].append(inetnum_temp[1])
            network["org"].append(netname[1])
            network["netname"].append(netname[1])
            network["country"].append(country[1])
            network["url"].append(inetnumurl)
    if rir == 'arin':
        inetnums = re.findall(r'NetRange.*', str(input))
        if not inetnums:
            arin_clean = str(arin).replace('\\n', ';')
            url = re.findall('(https://rdap.arin.net/registry/entity/.[^;]*)', arin_clean)
            entity_page = requests.get(url[0])
            country = re.search("Country\:\s+(\w+)", arin_clean)
            org = re.search("CustName\:\s+(.[^;]*)", arin_clean)
            json_try = json.loads(entity_page.content)
            entity_df = json_normalize(json_try)
            network_df = pd.DataFrame(entity_df['networks'][0])
            network = {"query":[], "CIDR":[], "inetnum":[], "org":[], "netname":[], "country":[], "url":[]}
            try:
                for item in network_df.loc(0):
                    iprange = item['startAddress'] + " - " + item['endAddress']
                    cidr = re.search("v4prefix\'\: \'(\d+\.\d+\.\d+\.\d+)\'\, \'length\'\: (\d+)", str(item['cidr0_cidrs']))
                    cidr_clean = cidr[1] + "/" + cidr[2]
                    netname = item['handle']
                    network["query"].append(org_name)
                    network["CIDR"].append(cidr_clean)
                    network["inetnum"].append(iprange)
                    network["org"].append(org[1])
                    network["netname"].append(netname)
                    network["country"].append(country[1])
                    network["url"].append(url[0])
            except:
                pass
        else:
            for item in inetnums:
                item = re.sub("\s{2,}", " ", item)
                item = item.replace('b"','')
                item = item.replace('\\n\\n\\n"', '')
                item = item.replace('\\n', ',')
                item = item.replace(',,', ',')
                item = item.replace('# Filtered,', ';')
                inetnums_clean.append(item)
            for item in inetnums_clean:
                iprange = re.search("NetRange\: (\d+\.\d+\.\d+\.\d+ - \d+\.\d+\.\d+\.\d+)", item)
                cidr_clean = re.search("CIDR\:(.[^,]*),", item)
                org = re.search("Customer\:(.[^,]*),", item)
                if not org:
                    org = re.search("Organization\:(.[^,]*),", item)
                netname = re.search("NetName\:(.[^,]*),", item)
                country = re.search("Country\:(.[^,]*),", item)
                inetnumurl = re.search("Ref\:(.[^,]*),", item)
                network["query"].append(name)
                network["CIDR"].append(cidr_clean[1])
                network["inetnum"].append(iprange[1])
                network["org"].append(org[1])
                network["netname"].append(netname[1])
                network["country"].append(country[1])
                network["url"].append(inetnumurl[1])
    return(network)

def getLACNIC():
    data_file = requests.get('http://irr.lacnic.net/lacnic.db.gz')
    clean_file = gzip.decompress(data_file.content)
    clean_data = str(clean_file).replace('\\n', ';')
    clean_data = str(clean_data).replace(';;', '%%')
    entries = re.findall('(route\:.[^%]*)%%', clean_data)
    data = []
    for entry in entries:
        entry = entry.replace('LACNIC generated route for ', '')
        route = re.findall('route\:\s+(.[^;]*);', entry)
        org = re.findall('descr\:\s+(.[^;]*);', entry)
        asn = re.findall('origin\:\s+(.[^;]*);', entry)
        data_string = route[0] + "; " + org[0] + "; " + asn[0]
        data.append(data_string)
    return(data)

results = []
lacnic_data = getLACNIC()

# Check for names containing '&' or 'and' to search for both instances
org_name_array = []
if ' ' in org_name:
    no_spaces = org_name.replace(' ', '')
    org_name_array.append(no_spaces)
if ' & ' in org_name:
    org_name_array.append(org_name)
    temp_org_name =(org_name.replace('&', 'and'))
    org_name_array.append(temp_org_name)
elif ' and ' in org_name:
    org_name_array.append(org_name)
    temp_org_name =(org_name.replace('and', '&'))
    org_name_array.append(temp_org_name)
else:
    org_name_array.append(org_name)
    
#do the work
results = []
for org_name in org_name_array:
    #RIPE NCC query function
    ripe = subprocess.check_output(['whois', '-h', 'whois.ripe.net', org_name])
    if str(ripe) != "b''":
        ripe_results = cleanRIROuput(org_name, ripe, 'ripe')
        results.append(pd.DataFrame(ripe_results))
    
    #APNIC Query
    apnic = subprocess.check_output(['whois', '-h', 'whois.apnic.net', org_name])
    if "ERROR:" not in str(apnic):
        apnic_results = cleanRIROuput(org_name, apnic, 'apnic')
        results.append(pd.DataFrame(apnic_results))

    #AfriNIC Query
    afrinic = subprocess.check_output(['whois', '-h', 'whois.afrinic.net', org_name])
    if "ERROR:" not in str(afrinic):
        afrinic_results = cleanRIROuput(org_name, afrinic, 'afrinic')
        results.append(pd.DataFrame(afrinic_results))
    
    #ARIN Query
    arin_query = 'whois -h whois.arin.net "+ z *' + org_name + '*"'
    arin = subprocess.check_output(arin_query, shell=True)
    if "No match found for" not in str(arin):
        asns = re.findall("OriginAS\:\s*([\w,\s]*).+Organization:", str(arin))
        arin_results = cleanRIROuput(org_name, arin, 'arin')
        results.append(pd.DataFrame(arin_results))
        
    #LACNIC Query
    matches = []
    for item in lacnic_data:
        pattern = ".*" + org_name + ".*"
        matched = re.search(pattern, item, re.IGNORECASE)
        try:
            matches.append(matched[0])
        except:
            pass
    if matches:
        df1 = pd.DataFrame()
        df = pd.DataFrame(matches)
        df1[["CIDR", "org", "inetnum"]] = df[0].astype("string").str.split("; ", expand=True)
        df1["query"] = org_name
        df1[["netname", "country", "url"]] = "unknown"
        final_df = df1[['query', 'CIDR', 'inetnum', 'org', 'netname', 'country', 'url']]
        results.append(pd.DataFrame(final_df))

try:
    final_results = pd.concat(results)        
    if output:
        filepath = Path(output)  
        final_results.to_csv(filepath)  
    else:            
        try:
            print(tabulate(final_results, headers="keys", tablefmt="fancy_grid"))
        except:
            output = org_name + ".csv"
            filepath = Path(output)  
            final_results.to_csv(filepath)  
            print("Error outputing results to terminal. Results saved to " + output + ".")
            
except:
    print('No results found for ' + org_name + '.')
