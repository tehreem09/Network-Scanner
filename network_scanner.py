import argparse
import scapy.all as scapy

def arg_handler():
    parser = argparse.ArgumentParser(description="Find MAC of target(s) on the same network.")
    parser.add_argument("-t","--target", dest="ip", help="target's ip or subnet mask")
    values = parser.parse_args()
    return values.ip

def create_packet(ip):
    arp = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    response = broadcast/arp
    up_ip_list , down_ip_list = scapy.srp(response,timeout=1,verbose=False)
    return up_ip_list

def print_result(up_ip_list):
    targets = []
    for x in up_ip_list:
        target_info = {"ip":x[1].psrc,
        "mac":x[1].hwsrc}
        targets.append(target_info)
    print("\n ip\t\t\tMAC address")
    print("----------------------------------------------------------")
    for target in targets:
        print(target["ip"]+"\t\t"+target["mac"])


print_result(create_packet(arg_handler()))