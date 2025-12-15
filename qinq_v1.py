#!/usr/bin/env python3
"""

qinq v1.0 [20251114]

Script to bridge end hosts over QinQ

by Terence LEE <telee.hk@gmail.com>

https://github.com/telee0/poc_scripts
https://scapy.net

"""

from scapy.all import *
import threading
import time

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, Dot1Q

conf.L3socket = L3RawSocket  # key for local injection

# --------- --------- --------- --------- --------- --------- --------- ---------

cf = {
    's_vlan': 100,
    'c_vlans': [100, 200, 300, 400, 500],  # , 600]
    'ethertype': None,  # 0x88a8, or None for default 0x8100
    'sniff_filter_in': "vlan and ether dst host {}",
    'sniff_filter_out': "not vlan and ether src host {}",
    'version': "1.0 [20251114]",
    'verbose': True,
    'debug': False,
}

hosts = {
    'tl-ubuntu-01': {
        'ip': "1.1.0.236",
        'mac': "64:9d:99:b1:12:3a",
        'iface': 'ens192',
    },
    'tl-ubuntu-02': {
        'ip': "1.1.0.237",
        'mac': "64:9d:99:b1:12:3b",
        'iface': 'ens192',
    },
    'tl-ubuntu-03': {
        'ip': "1.1.0.238",
        'mac': "64:9d:99:b1:12:3c",
        'iface': 'ens192',
    },
    'tl-ubuntu-04': {
        'ip': "1.1.0.239",
        'mac': "64:9d:99:b1:12:3d",
        'iface': 'ens192',
    },
    'ubuntu-236': {
        'ip': "1.1.0.236",
        'mac': "bc:24:11:59:2b:af",
        'iface': 'enp6s19',
    },
    'ubuntu-237': {
        'ip': "1.1.0.237",
        'mac': "bc:24:11:12:d6:b1",
        'iface': 'enp6s19',
    },
}

me = {}
verbose, debug = cf['verbose'], cf['debug']

# --------- --------- --------- --------- --------- --------- --------- ---------

def arp_add(ip_mac_dict, iface):
    func = "arp_add"

    for ip in ip_mac_dict.keys():
        mac = ip_mac_dict[ip]

        cmd_add = ["sudo", "ip", "neigh", "replace", ip, "lladdr", mac, "dev", iface, "nud", "permanent"]
        result = subprocess.run(cmd_add, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"[{func}] Failed to add {ip} -> {mac}")
            print(result.stderr)

    print("Current ARP table:\n")
    print(subprocess.getoutput("ip neigh show"))

    for ip in ip_mac_dict.keys():
        mac = ip_mac_dict[ip]

        # cmd_check = ["ip", "neigh", "show", ip, "dev", iface, "nud", "permanent"]
        cmd_check = ["ip", "neigh", "show", ip]
        result = subprocess.run(cmd_check, capture_output=True, text=True)

        if ip in result.stdout and mac.lower() in result.stdout.lower():
            print(f"[{func}] {ip} -> {mac}")
        else:
            print(f"[{func}] Entry not found for {ip} → {mac}")

    print()


def init():
    global me
    global verbose  # , debug

    ip2mac, mac2ip = {}, {}

    # find myself from the host list
    #
    iface_list = get_if_list()
    for host_name in hosts.keys():
        host = hosts[host_name]
        if 'iface' in host and host['iface'] in iface_list:
            mac = get_if_hwaddr(host['iface'])
            if 'mac' in host and mac.lower() == host['mac'].lower():
                ip = get_if_addr(host['iface'])
                if 'ip' in host and ip == host['ip']:
                    me = {
                        'name': host_name,
                        'ip': host['ip'],
                        'mac': host['mac'],
                        'iface': host['iface'],
                    }
                    break

    if not me:
        print("Host not identified. Please check your configuration.")
        exit(1)

    cf['vlan_layers'] = len(cf['c_vlans']) + 1

    # check cf['s_vlan']
    #
    if 's_vlan' not in cf:
        print("S-VLAN not defined. Please check your configuration.")
        exit(1)
    else:
        s_vlan = cf['s_vlan']
        if type(s_vlan) is not int or s_vlan < 1 or s_vlan > 4094:
            print(f"S-VLAN {s_vlan} invalid. Please check your configuration.")
            exit(1)

    # Cache IP-to-MAC and MAC-to-IP mappings
    #
    for host_name in hosts.keys():
        host = hosts[host_name]
        ip2mac[host['ip']] = host['mac']
        mac2ip[host['mac']] = host['ip']

    del ip2mac[me['ip']]
    del mac2ip[me['mac']]

    # Add static ARP entries with OS `arp -s` commands
    #
    arp_add(ip2mac, me['iface'])

    if debug:
        print("IP-to-MAC mapping")
        for ip in ip2mac.keys():
            print(f"{ip} -> {ip2mac[ip]}")
        print("MAC-to-IP mapping")
        for mac in mac2ip.keys():
            print(f"{mac} -> {mac2ip[mac]}")
        print()


def encap(pkt):
    if IP not in pkt:
        return pkt

    ip = pkt[IP].copy()

    del ip.len
    del ip.chksum
    if TCP in ip:
        del ip[TCP].chksum
    if UDP in ip:
        del ip[UDP].chksum
    if ICMP in ip:
        del ip[ICMP].chksum

    p = Ether(src=pkt[Ether].src, dst=pkt[Ether].dst)
    if 'ethertype' in cf and cf['ethertype'] == 0x88a8:
        p /= Dot1Q(vlan=cf['s_vlan'], type=cf['ethertype'])
    else:
        p /= Dot1Q(vlan=cf['s_vlan'])  # 0x8100
    for c_vlan in cf['c_vlans']:
        p /= Dot1Q(vlan=c_vlan)

    p /= ip

    if debug:
        print("p:", bytes(p).hex())

    return p


def decap(pkt):
    if IP not in pkt:
        return pkt

    p = pkt.copy()

    vlans = []

    while Dot1Q in p:
        vlans.append(p[Dot1Q].vlan)
        p = p[Dot1Q].payload

    if debug:
        print("decap: VLAN stack ==", vlans[::-1])

    ip = p[IP]

    del ip.len
    del ip.chksum
    if TCP in ip:
        del ip[TCP].chksum
    if UDP in ip:
        del ip[UDP].chksum
    if ICMP in ip:
        del ip[ICMP].chksum

    # p = Ether(src=pkt[Ether].src, dst=pkt[Ether].dst) / ip
    p = ip

    if debug:
        print("pkt:", bytes(pkt).hex())
        print("p:", bytes(p).hex())

    return p


def outbound(pkt):
    if verbose:
        print("[outbound]")
    p = encap(pkt)
    sendp(p, iface=me['iface'], verbose=0)
    if verbose:
        print(f"outbound: {p.summary()}")


def inbound(pkt):
    if verbose:
        print("[inbound]")
    p = decap(pkt)
    send(p, verbose=1)  # layer-3 send() to forward the packet to the local process on the same host
    if verbose:
        print(f"inbound: {p.summary()}")


def sniff_outbound():
    global cf, me
    filter_bpf = cf['sniff_filter_out'].format(me['mac'].replace(':', ''))
    if verbose:
        print("[sniff_outbound]")
        print("outbound BPF filter:", filter_bpf)
    sniff(
        iface=me['iface'],
        prn=outbound,
        filter=filter_bpf,
        store=0
    )


def sniff_inbound():
    global cf, me
    filter_bpf = cf['sniff_filter_in'].format(me['mac'].replace(':', ''))
    if verbose:
        print("[sniff_inbound]")
        print("inbound BPF filter:", filter_bpf)
    sniff(
        iface=me['iface'],
        prn=inbound,
        filter=filter_bpf,
        store=0
    )


if __name__ == "__main__":
    print(f"QinQ Tunneling Proxy v{cf['version']}\n")

    init()

    print("Host name:", me['name'])
    print("Interface:", me['iface'])
    print("MAC address:", me['mac'])
    print("IP address:", me['ip'])
    print("VLAN stack:", cf['c_vlans'])
    print()

    threading.Thread(target=sniff_outbound, daemon=True).start()
    threading.Thread(target=sniff_inbound,  daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[Tunnel stopped]")
