#!/usr/bin/python3
"""
   This code was created to integrate Kytos napps with Zabbix

   Created on: Dec/2020
   Author: Italo Valcy

   Changelog:
     - 2020/12/10 - Creating the script for monitoring items of Kytos similar to oess_zabbix.py
     - 2020/12/15 - adding option to export EVC statistics (bytes and packets)
     - 2022/11/30 - bug fixes and integration with kytos-ng/flow_stats rather than flow_manager

"""

import os
import sys
import json
import argparse
import requests
import time

url='http://192.168.0.1:8181/api'

CACHE_DIR='/var/cache/kytos_zabbix'
cache = {
 1: CACHE_DIR + '/nodes.json',
 2: CACHE_DIR + '/links.json',
 3: CACHE_DIR + '/evcs.json',
 4: CACHE_DIR + '/flows.json',
 5: CACHE_DIR + '/flows.json',
}

help_msg = "Kytos wrapper for Zabbix"

parser = argparse.ArgumentParser()
parser.add_argument("-l", "--url", dest="url", help="URL for your Kytos REST API", default=url)
parser.add_argument("-u", "--user", dest="username", help="Username to authenticate into Kytos API")
parser.add_argument("-p", "--pass", dest="password", help="Password to authenticate into Kytos API")
parser.add_argument("-f", "--authfile", dest="authfile", help="Authentication file containing username (first line) and password (second line) to authenticate into Kytos API")
parser.add_argument("-T", "--timeout", dest="timeout", type=int, help="You can tell Requests to stop waiting for a response after a given number of seconds", default=5)
parser.add_argument("-c", "--cache_policy", dest="cache_policy", default=60, help="Cache policy: never, always or X seconds (default to cache for 600 seconds)")
parser.add_argument("-o", "--monitoring_option", dest="option", type=int, default=1, choices=[1, 2, 3, 4, 5], help="Monitoring option: 1 - for monitor nodes, 2 - for monitor links, 3 - for monitor evcs (status), 4 - evc statistics, 5 - OpenFlow flows stats")
parser.add_argument("-t", "--target", dest="target", help="Item status (0-down/others, 1-disabled, 2-up/primary, 3-up/backup). Argument is the item id to be monitored (depending on the -o option).")
parser.add_argument("-z", "--zabbix_output", dest="count_output", type=int, choices=[1, 2], help="Zabbix LLD: (1) Count number of lines in each output or (2) list-only registers", default=None)
parser.add_argument("-s", "--stats", dest="stats", type=int, default=1, choices=[1, 2, 3, 4], help="EVC statistics type: 1 - bytes/UNI_A, 2 - bytes/UNI_Z , 3 - packets/UNI_A, 4 - packets/UNI_Z")

args = parser.parse_args()

if args.option == 4 and not args.target:
    sys.stderr.write('error: to print statistics it requires -t\n')
    parser.print_help()
    sys.exit(2)

if args.authfile:
    authdata = open(args.authfile).readlines()
    args.username = authdata[0].strip()
    args.password = authdata[1].strip()

args.url = os.environ.get("KYTOS_URL", args.url)
args.timeout = os.environ.get("KYTOS_TIMEOUT", args.timeout)
args.username = os.environ.get("KYTOS_USERNAME", args.username)
args.password = os.environ.get("KYTOS_PASSWORD", args.password)

def is_valid_cache(option):
    filename = cache[option]
    if not os.path.isfile(filename) or os.path.getsize(filename) == 0:
        return False
    if args.cache_policy == 'never':
        return False
    elif args.cache_policy == 'always':
        return True
    try:
        tmout = int(args.cache_policy)
    except:
        tmout = 600
    return os.stat(filename).st_mtime > time.time() - tmout

def get_data(option, url):
    if is_valid_cache(option):
        with open(cache[option], 'r') as file:
            return file.read()

    auth = None
    if args.username and args.password:
        auth = (args.username, args.password)  # assume HTTP Basic

    try:
        response = requests.get(url, auth=auth, timeout=args.timeout)
        assert response.status_code == 200, response.text
        data = response.text
    except Exception as e:
        print("ERROR: failed to get data from URL=%s: %s" % (url, e))
        sys.exit(2)

    if args.cache_policy != 'never':
        with open(cache[option], 'w') as file:
            file.write(data)
    return data

def get_kytos_data(url, option):
    API_ENDPOINT = ""
    if option == 1:
        API_ENDPOINT="/kytos/topology/v3/switches"
    elif option == 2:
        API_ENDPOINT="/kytos/topology/v3/links"
    elif option == 3:
        API_ENDPOINT="/kytos/mef_eline/v2/evc"
    elif option in [4,5]:
        API_ENDPOINT="/amlight/flow_stats/v1/flow/stats"

    data = get_data(option, url + API_ENDPOINT)
    try:
        data = json.loads(data)
        if option == 1:
            data = data["switches"]
        elif option == 2:
            data = data["links"]
    except Exception as e:
        print("ERROR: failed to get data from URL=%s: %s" % (url + API_ENDPOINT, e))
        sys.exit(2)

    return data

def convert_status(active, enabled):
    if active:
        return "2"
    elif not enabled:
        return "1"
    else:
        return "0"

def print_target_results(data, option, target):
    if target not in data:
        print("Unknown target=%s" % (target))
        return

    if option == 1:
        sw = data[target]
        print(convert_status(sw["active"], sw["enabled"]))
    elif option == 2:
        link = data[target]
        print(convert_status(link["active"], link["enabled"]))
    elif option == 3:
        evc = data[target]
        status = convert_status(evc["active"], evc["enabled"])
        if status != "2" or evc.get("dynamic_backup_path", False):
            print(status)
            return
        if evc["current_path"] == evc["primary_path"]:
            print("2")
        elif evc["current_path"] == evc["backup_path"]:
            print("3")
        else:
            print("0")

def print_flow_stats(data, target):
    if target:
        print(len(data.get(target, [])))
    else:
        l = 0
        for s in data:
            l+= len(data[s])
        print(l)

def print_stats(flows, target, stats_type):
    evcs = get_kytos_data(args.url, 3)
    if target not in evcs:
        print("Unknown target=%s" % (target))
        return

    uni_field = 'uni_a'
    if stats_type in [2,4]:
        uni_field = 'uni_z'
    stats_field = 'byte_count'
    if stats_type in [3, 4]:
        stats_field = 'packet_count'

    uni = evcs[target][uni_field]['interface_id'].split(':')
    sw = ':'.join(uni[:-1])
    iface = int(uni[-1])
    try:
        tag = evcs[target][uni_field]['tag']['value']
    except:
        tag = None

    result = 0
    for flow_id, flow in flows.get(sw, {}).items():
        if format(flow['cookie'], 'x')[2:] == target and flow['match']['in_port'] == iface and flow['match'].get('dl_vlan') == tag:
            result += flow[stats_field]

    print(result)

def list_items(data, option):
    result = {"data":[]}
    if option == 1:
        for sw in data:
            name = data[sw]["metadata"].get("name", None)
            if not name:
                name = data[sw]["name"]
            result["data"].append({"{#OFSWID}": sw, "{#OFSWNAME}": name})
    elif option == 2:
        for l in data:
            link = data[l]
            name = link.get("name", None)
            if not name:
                name = link["endpoint_a"]["name"] + "_" +  link["endpoint_b"]["name"]
            result["data"].append({"{#LINKID}": l, "{#LINKNAME}": name})
    elif option == 3:
        for evc in data:
            result["data"].append({"{#EVCID}": evc, "{#EVCNAME}": data[evc]["name"]})
    print(json.dumps(result))

data = get_kytos_data(args.url, args.option)

if args.option == 4:
    print_stats(data, args.target, args.stats)
elif args.option == 5:
    print_flow_stats(data, args.target)
elif args.target:
    print_target_results(data, args.option, args.target)
elif args.count_output == 1:
    # Count amount of items
    print(len(data))
elif args.count_output == 2:
    # List in JSON format. Don't show status!
    list_items(data, args.option)
else:
    parser.print_help()
