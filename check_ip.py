#!/usr/bin/env python3

# Stanislas M. 2024-07-05

"""
usage: check_ip.py [-h] [-a IP] [-i INPUT_FILE]

Get IP information

options:
  -h, --help            show this help message and exit
  -a IP, --ip-address IP
                        IP address to check
  -i INPUT_FILE, --input-file INPUT_FILE
                        File containing IP addresses to check
"""

import requests
import argparse
import json
import time
from bs4 import BeautifulSoup
from prettytable import PrettyTable
import csv
from spur_us_api import process_ip_with_spur

# disable ssl warning in case of proxy like Zscaler which breaks ssl...
requests.packages.urllib3.disable_warnings()

# Read secrets from "secrets.json"
def read_secrets():
    with open('secrets.json') as f:
        secrets = json.load(f)
    return secrets

secrets = read_secrets()

# fill proxy here
proxy = secrets["proxy_url"]

proxies = { 'http': proxy, 'https': proxy }

def get_ipinfo(ip):
    ipinfo_url = f"https://ipinfo.io/{ip}"
    headers={"Authorization": f"Bearer {secrets['ipinfo_token']}"}
    ipinfo_data = requests.get(ipinfo_url, headers=headers, proxies=proxies, verify=False)
    return ipinfo_data
    

def get_spur(ip):
    spur_url = f"https://spur.us/context/{ip}"
    spur_data = requests.get(spur_url, proxies=proxies, verify=False)
    # print(spur_data.text)

    soup = BeautifulSoup(spur_data.text, 'html.parser')
    title_tag = soup.title
        
    if title_tag is not None:
        title_text = title_tag.get_text()
            
        if "(" in title_text and ")" in title_text:
            content = title_text.split("(")[1].split(")")[0].strip()
        else:
            content = "Not Anonymous"
    
    return content

def process_ip(ip):
    ipinfo_data = get_ipinfo(ip)
    ipinfo_json = json.loads(ipinfo_data.text)

    try:
        spur_ip = process_ip_with_spur(ip)["tunnels"]
        if spur_ip == "":
            spur_ip = "Not anonymous"
    except:
        spur_ip = "Not found"

    data = {
        "IP": ip,
        "City": ipinfo_json['city'],
        "Region": ipinfo_json['region'],
        "Country": ipinfo_json['country'],
        "Location": ipinfo_json['loc'],
        "ISP": ipinfo_json['org'],
        "Postal": ipinfo_json['postal'] if 'postal' in ipinfo_json else "Unknown",
        "Timezone": ipinfo_json['timezone'],
        "VPN Vendor (Spur)": spur_ip  #get_spur(ip)
    }

    table = PrettyTable()
    table.field_names = ["Key", "Value"]

    for key, value in data.items():
        table.add_row([key, value])

    print(table)
    print("\n")

    return data

def write_to_csv(results, output_file):
    with open(output_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        for result in results:
            writer.writerow(result)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get IP information')
    parser.add_argument('-a', '--ip-address', dest='ip', help='IP address to check')
    parser.add_argument('-i', '--input-file', dest='input_file', help='File containing IP addresses to check')
    parser.add_argument('-o', '--output-file', dest='output_file', default='report.csv', help='Output CSV file')
    args = parser.parse_args()

    results = []

    try: 
        if args.ip:
            process_ip(args.ip)
        elif args.input_file:
            with open(args.input_file, 'r') as f:
                for line in f:
                    ip = line.strip()
                    result = process_ip(ip)
                    results.append(result)
                    time.sleep(1)

        if results:
            write_to_csv(results, args.output_file)
            print(f"Report written to {args.output_file}")

    except Exception as err:
        print("General error: " + str(err)) 
        exit(1)