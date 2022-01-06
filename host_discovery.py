import os
from log import logger 
import xml.etree.ElementTree as ET
import helper
import pdb

def discover_hosts(ranges, out_dir):
    hosts = {}
    # Via nmap ARP range scan
    for range in ranges:
        new_hosts = nmap_range_scan(range, out_dir)
        hosts.update(new_hosts)

    return hosts

def nmap_range_scan(range, out_dir):
    filename = os.path.join(out_dir, "range_scan")
    nmap_command = f"nmap {helper.nmap_exclude} -sn {helper.nmap_dns_arg} -oA '{filename}' {range}"
    os.makedirs(f"{os.path.dirname(filename)}", exist_ok=True)
    logger.info(f"Running: {nmap_command}")
    os.system(nmap_command)
    return parse_nmap_range_scan(filename+".xml")

def parse_nmap_range_scan(file_path):
    hosts = {}

    try:
        tree = ET.parse(file_path)
    except Exception as e:
        logger.error(f"ERROR parsing file: {file_path}. "+str(e))
        return {}

    xml_hosts = tree.findall("host[status]")

    for xml_host in xml_hosts:
        if not xml_host.find("status").attrib["state"] == 'up':
            continue

        if xml_host.find("status").attrib["reason"] == 'reset':
            continue

        ip = xml_host.find("address").attrib["addr"]
        tmp = xml_host.findall("hostnames/hostname")
        hostnames = []
        for t in tmp:
            hostnames.append(t.attrib["name"])

        if len(hostnames) > 0:
            for hostname in hostnames:
                host = {"ip": ip, "hostname": hostname, "comment": ""}
                hosts[helper.get_host_id(host)] = host
        else:
            host = {"ip": ip, "hostname": "unknown", "comment": ""}
            hosts[helper.get_host_id(host)] = host
    
    return hosts