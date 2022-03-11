import dns
import ipaddress
import os
import pdb

def get_host_id(target):
    if target["hostname"] and target["hostname"].lower() != "unknown":
        return target["hostname"].upper()
    else:
        return target['host_ip']

def target_to_foldername(target):
    host = get_host_id(target)
    return f"{host}___{target['comment']}"

def target_to_folderpath(target, out_dir):
    foldername=target_to_foldername(target)
    return os.path.join(out_dir, foldername)

def hostname_to_filepath(hostname, output_folder):
    for root, dirs, files in os.walk(output_folder):
        for dir in dirs:
            if dir.split("_")[0] == hostname.upper():
                return os.path.join(root, dir)
    
    return None

def get_aligned_ip(ip):
    ret = []
    for octet in ip.split("."):
        ret.append(f"{int(octet):03}")
    return ".".join(ret)

def is_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

def set_dns_preference(args):
    global nmap_dns_arg
    nmap_dns_arg = "--system-dns"
    if args.dns_server != "":
        nmap_dns_arg = f"--dns-server {args.dns_server}"

def set_nmap_excludes(args):
    global nmap_exclude
    nmap_exclude = ""
    if args.excluded_ips != '':
        nmap_exclude = "-excludefile "+args.excluded_ips
