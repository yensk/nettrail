import socket
from log import logger

def get_hostname_by_ipv4(ip):
    hostname = ip
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except:
        logger.info(f"[ ] Could not resolve {ip}.")
    return hostname

def get_ipv4_by_hostname(hostname):
    logger.debug("Resolving: "+hostname)
    # see `man getent` `/ hosts `
    # see `man getaddrinfo`

    try:
        return list(
            i        # raw socket structure
                [4]  # internet protocol info
                [0]  # address
            for i in 
            socket.getaddrinfo(
                hostname,
                0  # port, required
            )
            if i[0] is socket.AddressFamily.AF_INET  # ipv4

            # ignore duplicate addresses with other socket types
            and i[1] is socket.SocketKind.SOCK_RAW  
        )
    except:
        return []



