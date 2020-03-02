#! python3
# -*- coding: utf-8 -*-
import nmap
import ipaddress

def portscan(ip_address):
    """
    this function will scan a subnet, or single IP returning with
    up/down and any open TCP ports in the range 22-443
    :param: ip_address - single host, or slash notation subnet
    :return: none, printing results to screen
    """
    nm = nmap.PortScanner()
    nm.scan(ip_address, '21-443')
    ips = ipaddress.IPv4Network(ip_address)
    sortedhosts = sorted(nm.all_hosts())
    for host in ips:
        try:
            print(f'Host : {str(host)} {nm[str(host)].hostname()}')
            print(f'State : {nm[str(host)].state()}')
    
            for proto in nm[str(host)].all_protocols():
                print("-----------")
                print(f'Protocol : {proto}')

                lport = sorted(nm[str(host)][proto].keys())
                #lport.sort()
                for port in lport:
                    print(f'Port : {port}\tstate : {nm[str(host)][proto][port]["state"]}')
        except KeyError:
            pass
    print("\n")

if __name__ == "__main__":
    while True:
        choice = input("IP Addresses to scan [ex. 10.20.100.0/24, 10.1.5.55]: ")
        portscan(choice)
