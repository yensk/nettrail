import helper
import pdb

def export_targets_md(targets, hosts):
    pdb.set_trace()

    for t in targets:

        if "host_ip" not in t:
            continue
        if t["host_ip"] not in hosts:
            continue

        host = hosts[t["host_ip"]]

        ip = f"{host['host_ip']}"
        hostname = f"{host['hostname']}"
        for port in host["ports"].values():
            port_desc = " "+port["service"].get("name", "unknown")
            port_desc += " "+port["service"].get("product", "")
            port_desc += " "+port["service"].get("version", "")
            port_desc += " "+port["service"].get("extrainfo", "")

            print(f"| {ip:<15} | {hostname} | {port['portid']:>5}| {port_desc} |")
            ip = ""
            hostname = ""

def sanitize_latex_control_symbols(line):
    return line.replace("_", "\_").replace("&","\&").replace("#","\#")

def export_targets_latex(targets, hosts):
    
    print("\\begin{longtable}{R{1cm}|L{11.9cm}}")

    for t in targets:
        t = t.strip().upper()
        host = None
        for h in hosts:
            if hosts[h]["host_ip"] == t or hosts[h]["hostname"].upper() == t:
                host = hosts[h]
                break
        if host == None:
            continue

        ip = f"{host['host_ip']}"
        hostname = f"{host['hostname']}"
        if len(host["ports"]) == 0:
            continue

        print("")
        print('\multicolumn{2}{l}{\cellcolor{lightgray} \\textbf{'+ip+' ('+hostname+')}} \\\\ ')
        print("\\toprule")
        print("Port & Service\\\\")
        print("\\toprule")

        for port in host["ports"].values():
            port_desc = " "+port["service"].get("name", "unknown")
            port_desc += " "+port["service"].get("product", "")
            port_desc += " "+port["service"].get("version", "")
            port_desc += " "+port["service"].get("extrainfo", "")

            print(f"{port['portid']:>5} & {sanitize_latex_control_symbols(port_desc)} \\\\")
            ip = ""
            hostname = ""
        print("\\multicolumn{2}{l}{}\\\\")
    print("\\end{longtable}")