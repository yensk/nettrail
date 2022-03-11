#!/usr/bin/python3

import os
from argparse import RawTextHelpFormatter,ArgumentParser, ArgumentDefaultsHelpFormatter
import xml.etree.ElementTree as ET
import dns
import nmap_analyzer
import host_discovery
import log
from log import logger
import shutil
import helper
import pdb
import exporter

def discover(arguments):
    logger.debug("DISCOVER MODE")
    logger.debug("=============")
    logger.debug("")
    helper.set_dns_preference(arguments)
    helper.set_nmap_excludes(arguments)

    input_data = arguments.ip_ranges
    if arguments.ip_file != '':
        with open(arguments.ip_file, "r") as f:
            input_data.extend(f.readlines())

    ranges = parse_raw_targets(input_data)
    hosts = host_discovery.discover_hosts(ranges, out_dir)
    for host in hosts:
        logger.info(helper.get_host_id(hosts[host]))

def scan(arguments):
    logger.debug("SCAN MODE")
    logger.debug("=========")
    logger.debug("")
    helper.set_dns_preference(arguments)
    helper.set_nmap_excludes(arguments)

    partial_scan = arguments.partial_scan
    fast_scan = arguments.fast_scan
    batch_scan = arguments.batch_scan
    full_scan = not batch_scan and not fast_scan and not partial_scan

    input_data = arguments.hostnames

    if arguments.hostname_file != '':
        with open(arguments.hostname_file, "r") as f:
            input_data.extend(f.readlines())

    targets = parse_targets(input_data)
    if not os.geteuid() == 0:
        logger.error(f"To scan you have to run the program with root privileges.")
        exit()

    if batch_scan:
        batch_scan_ip(targets)

    for target in targets:
        combined_scan_results = nmap_analyzer.get_combined_scan_results(helper.target_to_folderpath(target, out_dir))
        scan_results = False
        
        if partial_scan:
            scan_results = partial_scan_ip(target)
        elif fast_scan:
            scan_results = fast_scan_ip(target)
        elif full_scan:
            scan_results = full_scan_ip(target)

        combined_scan_results = nmap_analyzer.join_host_info(combined_scan_results, scan_results)

        if len(combined_scan_results["ports"]) > 0:
            scan_results = detailed_scan_ip(target, combined_scan_results["ports"])
        logger.info(f"    [P] {nmap_analyzer.get_ports_fingerprint(scan_results['ports'])}")

def analyze(arguments):
    logger.debug("ANALYSIS MODE")
    logger.debug("=============")
    logger.debug("")
    fil = nmap_analyzer.Filter()
    if arguments.hostname_file != '':
        with open(arguments.hostname_file, "r") as f:
            input_data = f.readlines()
    if arguments.filter_hosts:
        if len(input_data) == 0:
            logger.error("You have to supply the allowed hosts in via -i.")
            exit()
        raw_targets = parse_raw_targets(input_data)
        fil.whitelist_hosts = raw_targets
    if arguments.filter_top1000:
        fil.whitelist_ports = nmap_analyzer.top1000_ports
    elif arguments.filter_not_top1000:
        fil.blacklist_ports = nmap_analyzer.top1000_ports

    hosts = nmap_analyzer.parse_all_hosts(out_dir, fil)

    if arguments.operation == "classes":
        nmap_analyzer.find_eq_classes(hosts, out_dir)
    if arguments.operation == "flatlist":
        services = nmap_analyzer.generate_flat_service_list(hosts, out_dir)

def cleanup(arguments):
    logger.debug("CLEANUP MODE")
    logger.debug("============")
    logger.debug("")
    input_data = arguments.targets
    if arguments.hostname_file != '':
        with open(arguments.hostname_file, "r") as f:
            input_data.extend(f.readlines())
    targets = parse_targets(input_data)
    clean_up_folders(targets, out_dir)

    clean_up_noports(targets, out_dir)

def show(arguments):
    logger.debug("SHOW MODE")
    logger.debug("============")
    logger.debug("")
    hostname = arguments.hostname[0]
    path = helper.hostname_to_filepath(hostname, out_dir)
    if path != None:
        path = os.path.join(path, "detailed_ports.nmap")
        if os.path.exists(path):    
            with open(path, "r") as f:
                logger.info("\r".join(f.readlines()))
            return
    logger.error(f"[-] No scan results exist for {hostname}")

def search(arguments):
    logger.debug("SEARCH MODE")
    logger.debug("============")
    logger.debug("")

    if len(arguments.search_str) > 0:
        search_str = arguments.search_str[0]
    else:
        search_str = ""

    ports = set()
    for x in arguments.ports.split(","):
        if x.strip() != '':
            ports.add(int(x.strip()))

    logger.info(f"[+] Searching for: '{search_str}' in hosts that have one port of [{','.join([str(x) for x in ports])}] open.")

    hosts = nmap_analyzer.find_hosts(search_str, ports, out_dir)
    logger.info("\n".join(sorted(hosts)))

def export(arguments):
    logger.debug("EXPORT MODE")
    logger.debug("============")
    logger.debug("")
    input_data = arguments.targets
    if arguments.hostname_file != '':
        with open(arguments.hostname_file, "r") as f:
            input_data.extend(f.readlines())
    targets = input_data
    hosts = nmap_analyzer.parse_all_hosts(out_dir)

    exporter.export_targets_latex(targets, hosts)




def clean_up_folders(targets, directory):
    for target in targets:
        dest_folder = helper.target_to_foldername(target)
        dummy_target = target.copy()
        dummy_target["comment"] = ""

        src_folder_prefix = helper.target_to_foldername(dummy_target)[:-2]
        logger.debug(f"Searching for folder prefix '{src_folder_prefix}'")
        for root, dirs, files in os.walk(directory):
            for dir in dirs:
                if dir.startswith(src_folder_prefix):
                    if dir != dest_folder:
                        logger.info(f"Moving '{dir}' to '{dest_folder}'")
                        shutil.move(os.path.join(root,dir),os.path.join(root,dest_folder))

def clean_up_noports(targets, directory):
    for root, dirs, files in os.walk(directory):
        for n in ("all_ports.xml", "partial_ports.xml", "detailed_ports.xml", "fast_ports.xml"):
            path = os.path.join(root, n)
            if os.path.exists(path):
                tmp = nmap_analyzer.parse_nmap_xml(path)
                if tmp == False:
                    print(f"[!] File '{path}' could not be parsed. Delete (Y/n)?")
                    r=input()
                    if r.lower() != "n":
                        os.remove(path)
                elif len(tmp["ports"]) == 0:
                    print(f"[!] File '{path}' does not contain open ports. Delete (y/N)?")
                    r=input()
                    if r.lower() == "y":
                        os.remove(path)

def get_nmap_target(target):
    if target["hostname"] != "" and target["hostname"].lower() != "unknown":
        return target["hostname"]
    return target["host_ip"]

def single_target_scan(filename, nmap_arguments, ports=None):
    scan_exists, ports_to_scan = nmap_analyzer.nmap_xml_is_finished_run(filename+".xml", ports)
    if not scan_exists:
        nmap_scan(filename, nmap_arguments, ports_to_scan)    
    else:
        logger.info(f"    [ ] {filename} already exists. Skipping port scan.")
    
    return nmap_analyzer.parse_nmap_xml(filename+".xml")

def nmap_scan(filename, nmap_arguments, ports_to_scan=None):
    os.makedirs(f"{os.path.dirname(filename)}", exist_ok=True)
    port_arg = ""
    if ports_to_scan != None:
        port_arg = f"-p{','.join([str(i) for i in ports_to_scan])}"
    nmap_command = f"nmap -vvvv {helper.nmap_exclude} {helper.nmap_dns_arg} {port_arg} -oA '{filename}' {nmap_arguments}"

    logger.info(f"    [ ] Running: {nmap_command}")
    os.system(nmap_command)

def split_batch_results(filepath, targets, filename):
    outfile = None
    with open(filepath+".nmap", "r") as f:
        lines = f.readlines()
        for line in lines:
            if line.startswith("Nmap scan report for "):

                # hostname and IP present
                if line.strip().endswith(")"):
                    ip = line.strip()[line.rfind("(")+1:-1]
                    tmp = line[:line.rfind("(")-1]
                    hostname = tmp[tmp.rfind(" ")+1:]
                # No hostname present
                else:
                    hostname = ""
                    tmp = line.strip()
                    ip = tmp[tmp.rfind(" ")+1:]
                
                target = None
                for t in targets:
                    if t["host_ip"] == ip or t["hostname"] == hostname:
                        target = t 
                        break
                
                if outfile != None:
                    outfile.close()
                
                target_folder = os.path.join(out_dir,helper.target_to_foldername(target))
                os.makedirs(target_folder, exist_ok=True)
                outfile = open(os.path.join(target_folder, filename+".nmap"), "w")
            if outfile != None:
                outfile.write(line)

    start = ""
    end = ""
    hosts=[]
    is_start = True
    is_end = False
    is_host = False
    cur_host = ""
    with open(filepath+".xml", "r") as f:
        lines = f.readlines()
        for line in lines:
            if line.startswith("<host "):
                is_host = True
                is_start = False
                is_end = False

            
            if is_start:
                start += line
            if is_end:
                end += line
            if is_host:
                cur_host += line
            
            if line.startswith("</host>"):
                is_host = False
                is_start = False
                is_end = True
                hosts.append(cur_host)
                cur_host = ""

    
    for host in hosts:
        target = None
        for t in targets:
            if t["host_ip"] in host or t["hostname"] in host:
                target = t
                break

        target_folder = helper.target_to_foldername(target)
        os.makedirs(target_folder, exist_ok=True)
        with open(os.path.join(out_dir,helper.target_to_foldername(target), filename+".xml"), "w") as o:
            o.write(start+host+end)

def batch_scan_ip(targets):
    logger.info(f"[+] FULL PORTSCAN on {','.join([t['hostname'] for t in targets])}")
    nmap_arguments = f"-p1-10 -T{arguments.aggressiveness} {' '.join([get_nmap_target(target) for target in targets])}"
    
    filename = "batch_ports"
    filepath = os.path.join(f"{out_dir}",filename)
    nmap_scan(filepath, nmap_arguments)

    split_batch_results(filepath, targets, filename)

def full_scan_ip(target):
    logger.info(f"[+] FULL PORTSCAN on {target['hostname']}")
    filename = os.path.join(f"{out_dir}",f"{helper.target_to_foldername(target)}","all_ports")
    nmap_arguments = f"-p- -T{arguments.aggressiveness} {get_nmap_target(target)}"
    return single_target_scan(filename, nmap_arguments)

def partial_scan_ip(target):
    logger.info(f"[+] PARTIAL PORTSCAN on {target['hostname']}")
    filename = os.path.join(f"{out_dir}",f"{helper.target_to_foldername(target)}",f"partial_ports")
    nmap_arguments = f"-T{arguments.aggressiveness} {get_nmap_target(target)}"
    return single_target_scan(filename, nmap_arguments)

def fast_scan_ip(target):
    logger.info(f"[+] FAST PORTSCAN on {target['hostname']}")
    filename = os.path.join(f"{out_dir}",f"{helper.target_to_foldername(target)}",f"fast_ports")
    nmap_arguments = f"-p- --min-rate 1000 -T4 {get_nmap_target(target)}"
    return single_target_scan(filename, nmap_arguments)

def detailed_scan_ip(target, ports):
    logger.info(f"[+] DETAILED PORTSCAN on {target['hostname']}")
    filename = os.path.join(f"{out_dir}",f"{helper.target_to_foldername(target)}",f"detailed_ports")
    nmap_arguments = f"-T{arguments.aggressiveness} -sC -sV {get_nmap_target(target)}"
    return single_target_scan(filename, nmap_arguments, ports)

def parse_raw_targets(lines):
    return [x.strip().split(" ")[0] for x in lines]

def parse_targets(lines):
    targets = []
    for line in lines:
        line = line.strip()
        tmp = line.split(" ")
        ip = tmp[0].strip()

        if len(ip) == 0:
            continue

        if len(tmp) > 1:
            comment = " ".join(tmp[1:])
        else:
            comment = ""
        
        if helper.is_ip(ip):
            targets.append({"host_ip": ip, "hostname": dns.get_hostname_by_ipv4(ip), "comment": comment})
        else:
            real_ips = dns.get_ipv4_by_hostname(ip)
            if(len(real_ips) == 0):
                logger.info("Could not resolve hostname: "+ip)
                continue
            targets.append({"host_ip": real_ips[0], "hostname":ip, "comment":comment})
    return targets




parser = ArgumentParser(description = 'nettrail, a tool to make nmap-based network recon digestable.', formatter_class = RawTextHelpFormatter)
parser.add_argument('-o', dest = 'output_path', help = 'Path where scan results are stored. (Default: ./output)', default = './output')
parser.add_argument('-v', dest = 'verbose', help = 'Enable verbose logging', action = 'store_true')

subparsers = parser.add_subparsers(title='Subcommands', help="", required=True)

discovery_parser = subparsers.add_parser('discover', help="Run in discover mode to find live hosts in the subnet")
discovery_parser.add_argument('-i', dest = 'ip_file', help = 'File that contains target IP ranges', default = '')
discovery_parser.add_argument('-e', dest = 'excluded_ips', help = 'File that contains IPs / IP subnets that must not be scanned', default = '')
discovery_parser.add_argument('-d', dest = 'dns_server', help = 'Use specified DNS server for reverse lookups', default = '')
discovery_parser.add_argument('ip_ranges', nargs = '*', help = 'Target IP ranges', default = []) 
discovery_parser.set_defaults(func=discover)

scan_parser = subparsers.add_parser('scan', help = 'Run in scan mode')
scan_parser.add_argument('-i', dest = 'hostname_file', help = 'File that contains target hostnames/IPs', default = '')
scan_parser.add_argument('-e', dest = 'excluded_ips', help = 'File that contains IPs / IP subnets that must not be scanned', default = '')
group = scan_parser.add_mutually_exclusive_group()
group.add_argument('-f', dest = 'fast_scan', help = 'Enable fast scan (might miss ports)', action='store_true')
group.add_argument('-p', dest = 'partial_scan', help = 'Enable partial scan', action = 'store_true')
group.add_argument('-b', dest = 'batch_scan', help = 'Enable batch scan', action = 'store_true')
scan_parser.add_argument('-a', dest = 'aggressiveness', help = 'Nmap aggressiveness', choices=["0","1","2","3","4","5"], default = '3')
scan_parser.add_argument('-d', dest = 'dns_server', help = 'Use specified DNS server for reverse lookups', default = '')
scan_parser.add_argument('hostnames', nargs = '*', help = 'Target hosts', default = []) 
scan_parser.set_defaults(func=scan)

show_parser = subparsers.add_parser('show', help = 'Show results for provided target')
show_parser.add_argument('hostname', nargs = '*', help = 'Target host', default = '') 
show_parser.set_defaults(func=show)

search_parser = subparsers.add_parser('search', help = 'Searches for hosts that have results which match search criteria')
search_parser.add_argument('-p', dest = 'ports', help = 'Only show systems that have one of the provided ports open. Comma seperated list, e.g., "80,443,8080"', default = '')
search_parser.add_argument('search_str', nargs = '*', help = 'Search string', default = '') 
search_parser.set_defaults(func=search)

analyze_parser = subparsers.add_parser('analyze', help = 'Analyze all performed scans.')
analyze_parser.add_argument('-H', dest = 'filter_hosts', help = 'Analysis should only be performed on the hosts that are supplied via -i.', action = 'store_true')
analyze_parser.add_argument('-i', dest = 'hostname_file', help = 'File that contains hostnames that should be analyzed', default = '')
analyze_parser.add_argument('-t', dest = 'filter_top1000', help = 'Analysis should only be based on top 1000 ports', action = 'store_true')
analyze_parser.add_argument('-T', dest = 'filter_not_top1000', help = 'Analysis should only be based on ports that are NOT in top 1000', action = 'store_true')
analyze_parser.add_argument('operation', help = "analysis operation to be performed. classes: show equivalence class view of all hosts. flatlist: show services of all hosts", default = '', choices=["classes","flatlist"]) 
analyze_parser.set_defaults(func=analyze)

cleanup_parser = subparsers.add_parser('cleanup', help='Update the folder names and check for inconsistent scanning results. If no targets are provided, all folders are scanned for inconsistent scanning results.')
cleanup_parser.add_argument('-i', dest = 'hostname_file', help = 'File that contains target IPs', default = '')
cleanup_parser.add_argument('targets', nargs = '*', help = "targets to be cleaned up.", default = []) 
cleanup_parser.set_defaults(func=cleanup)

export_parser = subparsers.add_parser('export', help='Exports scan results')
export_parser.add_argument('-i', dest = 'hostname_file', help = 'File that contains targets to be exported', default = '')
export_parser.add_argument('targets', nargs = '*', help = "Targets to be exported", default = []) 
export_parser.set_defaults(func=export)

arguments = parser.parse_args()

log.init_log(arguments.verbose)

out_dir = arguments.output_path

arguments.func(arguments)
