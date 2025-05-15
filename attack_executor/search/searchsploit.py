import argparse
import subprocess
import xml.etree.ElementTree as ET
import json
import sys
from attack_executor.scan.nmap import NmapExecutor


def search_exploits(query):
    # Run searchsploit with JSON output; return list of exploits.
    cmd = ["searchsploit", "--json", query]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    if res.returncode != 0 or not res.stdout:
        return []
    try:
        data = json.loads(res.stdout)
        return data.get("RESULTS_EXPLOIT", [])
    except json.JSONDecodeError:
        return []


def searchsploit(target):
    nmape = NmapExecutor()
    services = nmape.scan_xml(target=target)
    results = []

    for svc in services:
        # here we might want to parse the query to LLM for better searching
        query = " ".join(filter(None, [svc["name"], svc["product"], svc["version"]]))
        exploits = search_exploits(query)
        results.append({**svc, "exploits": exploits})

    return results

# raw_input = ['(microsoft_dns_6_1_7601_running 10.129.17.237)', '(kerberos_running 10.129.17.237)', '(msrpc_running 10.129.17.237)', '(netbios_ssn_running 10.129.17.237)', '(ad_ldap_running 10.129.17.237)', '(microsoft_ds_running 10.129.17.237)', '(msrpc_over_http_running 10.129.17.237)', '(mc_nmf_running 10.129.17.237)', '(microsoft_httpapi_2_0_running 10.129.17.237)']
# we parse it to LLM and let it decide which one to use
# then we parse the result to search_exploits
# then we return the result





