#!/usr/bin/env python3
"""

qinq v2.1 [20260126]

Script to bridge end hosts over QinQ

by Terence LEE <telee.hk@gmail.com>

https://github.com/telee0/poc_scripts
https://scapy.net

"""

from scapy.all import *
import threading
import time

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, Dot1Q

# conf.L3socket = L3RawSocket6  # key for local injection
sock_v4 = L3RawSocket()
sock_v6 = L3RawSocket6()

# --------- --------- --------- --------- --------- --------- --------- ---------

cf = {
    'qinq_vlans': [  # last ethertype will be ignored
        # (100, 0x8100), (100, 0x8100), (200, 0x8100), (300, 0x8100), (400, 0x8100), (500, 0x8100), (600, 0x8100),
        # (100, 0x8100), (100, 0x8100), (200, 0x88a8), (300, 0x88a8), (400, 0x88a8), (500, 0x88a8), (600, 0x88a8),
        # (100, 0x8100), (100, 0x8100), (200, 0x88a8), (300, 0x8100), (400, 0x88a8), (500, 0x8100), (600, 0x88a8),
        # (100, 0x8100), (100, 0x8100), (200, 0x8100), (300, 0x88a8), (400, 0x8100), (500, 0x88a8), (600, 0x8100),
        # (100, 0x88a8), (200, 0x8100), (300, 0x8100), (400, 0x8100), (500, 0x8100), (600, 0x8100),
        # (100, 0x88a8), (200, 0x88a8), (300, 0x88a8), (400, 0x88a8), (500, 0x88a8), (600, 0x88a8),
        # (100, 0x88a8), (200, 0x88a8), (300, 0x8100), (400, 0x88a8), (500, 0x8100), (600, 0x88a8),
        (100, 0x88a8), (200, 0x8100), (300, 0x88a8), (400, 0x8100), (500, 0x88a8), (600, 0x8100),
    ],
    'sniff_filter_in': "vlan and ether dst host {}",
    'sniff_filter_out': "not vlan and ether src host {}",
    'version': "2.1 [20260126]",
    'verbose': True,
    'debug': False,
    'neigh_add': {
        'v4': {
            'cmd_add': ["ip", "neigh", "replace", "{ip}", "lladdr", "{mac}", "dev", "{iface}", "nud", "permanent"],
            'cmd_check': ["ip", "neigh", "show", "{ip}"],
            'cmd_show': "ip -4 neigh show",
            'txt_neigh': "Current ARP table:\n",
        },
        'v6': {
            'cmd_add': ["ip", "-6", "neigh", "replace", "{ip}", "lladdr", "{mac}", "dev", "{iface}", "nud", "permanent"],
            'cmd_check': ["ip", "-6", "neigh", "show", "{ip}"],
            'cmd_show': "ip -6 neigh show",
            'txt_neigh': "Current IPv6 neighbor table:\n",
        },
    },
}

hosts = {
    'tl-ubuntu-01': {
        'ipv4': "1.1.0.236",
        'ipv6': "2001::236",
        'mac': "64:9d:99:b1:12:3a",
        'iface': 'ens192',
    },
    'tl-ubuntu-02': {
        'ipv4': "1.1.0.237",
        'ipv6': "2001::237",
        'mac': "64:9d:99:b1:12:3b",
        'iface': 'ens192',
    },
    'tl-ubuntu-03': {
        'ipv4': "1.1.0.238",
        'ipv6': "2001::238",
        'mac': "64:9d:99:b1:12:3c",
        'iface': 'ens192',
    },
    'tl-ubuntu-04': {
        'ipv4': "1.1.0.239",
        'ipv6': "2001::239",
        'mac': "64:9d:99:b1:12:3d",
        'iface': 'ens192',
    },
    'ubuntu-36': {
        'ipv4': "1.1.0.36",
        'ipv6': "2001::36",
        'mac': "bc:24:11:59:2b:af",
        'iface': 'enp6s19',
    },
    'ubuntu-37': {
        'ipv4': "1.1.0.37",
        'ipv6': "2001::37",
        'mac': "bc:24:11:12:d6:b1",
        'iface': 'enp6s19',
    },
}

me = {}
verbose, debug = cf['verbose'], cf['debug']

# --------- --------- --------- --------- --------- --------- --------- ---------

def neigh_add(ip_mac_dict, iface, ip_ver=4):
    func = "neigh_add"

    neigh = cf[func]['v' + str(ip_ver)]

    for ip, mac in ip_mac_dict.items():
        cmd_add = [s.format_map({'ip': ip, 'mac': mac, 'iface': iface}) for s in neigh['cmd_add']]
        result = subprocess.run(cmd_add, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"[{func}] Failed to add {ip} -> {mac}")
            print(result.stderr)

    print(neigh['txt_neigh'])

    if debug:
        print(subprocess.getoutput(neigh['cmd_show']))
        print()

    for ip, mac in ip_mac_dict.items():
        cmd_check = [s.format_map({'ip': ip}) for s in neigh['cmd_check']]
        result = subprocess.run(cmd_check, capture_output=True, text=True)

        if ip in result.stdout and mac.lower() in result.stdout.lower():
            print(f"[{func}] {ip} -> {mac}")
        else:
            print(f"[{func}] Entry not found for {ip} → {mac}")

    print()


def init():
    global me

    ip2mac_v4, mac2ip_v4 = {}, {}
    ip2mac_v6, mac2ip_v6 = {}, {}

    # find myself from the host list
    #
    iface_list = get_if_list()
    for host_name in hosts.keys():
        host = hosts[host_name]
        if 'iface' in host and host['iface'] in iface_list:
            mac = get_if_hwaddr(host['iface'])
            if 'mac' in host and mac.lower() == host['mac'].lower():
                ipv4 = get_if_addr(host['iface'])
                ipv6 = get_if_addr6(host['iface'])
                if 'ipv4' in host and ipv4 == host['ipv4']:
                    me = {
                        'name': host_name,
                        'ipv4': ipv4,
                        'mac': host['mac'],
                        'iface': host['iface'],
                    }
                if 'ipv6' in host and ipv6 == host['ipv6']:
                    if me:
                        me['ipv6'] = ipv6
                    else:
                        me = {
                            'name': host_name,
                            'ipv6': ipv6,
                            'mac': host['mac'],
                            'iface': host['iface'],
                        }
                if me:
                    break

    if not me:
        print("Host not identified. Please check your configuration.")
        exit(1)

    cf['n_vlans'] = len(cf['qinq_vlans'])

    # check cf['s_vlan']
    #
    '''
    if 's_vlan' not in cf:
        print("S-VLAN not defined. Please check your configuration.")
        exit(1)
    else:
        s_vlan = cf['s_vlan']
        if type(s_vlan) is not int or s_vlan < 1 or s_vlan > 4094:
            print(f"S-VLAN {s_vlan} invalid. Please check your configuration.")
            exit(1)
    '''

    # Cache IP-to-MAC and MAC-to-IP mappings
    #
    for host_name in hosts.keys():
        host = hosts[host_name]
        if 'ipv4' in host:
            ip2mac_v4[host['ipv4']] = host['mac']
            mac2ip_v4[host['mac']] = host['ipv4']
        if 'ipv6' in host:
            ip2mac_v6[host['ipv6']] = host['mac']
            mac2ip_v6[host['mac']] = host['ipv6']

    del ip2mac_v4[me['ipv4']]
    del mac2ip_v4[me['mac']]
    del ip2mac_v6[me['ipv6']]
    del mac2ip_v6[me['mac']]

    # Add static IP-to-MAC entries for neighbor hosts
    #
    neigh_add(ip2mac_v4, me['iface'], ip_ver=4)
    neigh_add(ip2mac_v6, me['iface'], ip_ver=6)

    if debug:
        print("IP-to-MAC mapping")
        for ip, mac in ip2mac_v4.items():
            print(f"{ip} -> {mac}")
        for ip, mac in ip2mac_v6.items():
            print(f"{ip} -> {mac}")
        print("MAC-to-IP mapping")
        for mac, ip in mac2ip_v4.items():
            print(f"{mac} -> {ip}")
        for mac, ip in mac2ip_v6.items():
            print(f"{mac} -> {ip}")
        print()


def encap(pkt):
    if IP in pkt:
        ip_ver = 4
        ip = pkt[IP].copy()
    elif IPv6 in pkt:
        ip_ver = 6
        ip = pkt[IPv6].copy()
    else:
        return pkt

    if ip_ver == 4:
        del ip.len
        del ip.chksum
    if TCP in ip:
        del ip[TCP].chksum
    if UDP in ip:
        del ip[UDP].chksum
    if ICMP in ip:
        del ip[ICMP].chksum

    p = Ether(src=pkt[Ether].src, dst=pkt[Ether].dst)

    n = cf['n_vlans'] - 1
    for i, tag in enumerate(cf['qinq_vlans']):
        if isinstance(tag, tuple):
            vlan, etype = tag
        else:
            vlan = tag
            etype = None
        if i == n:
            etype = None
        if etype is not None:
            p /= Dot1Q(vlan=vlan, type=etype)
        else:
            p /= Dot1Q(vlan=vlan)

    p /= ip

    if debug:
        print("p:", bytes(p).hex())

    return p


def decap(pkt):
    if IP in pkt:
        ip_ver = 4
    elif IPv6 in pkt:
        ip_ver = 6
    else:
        return pkt

    p = pkt.copy()

    vlans = []

    while Dot1Q in p:
        vlans.append(p[Dot1Q].vlan)
        p = p[Dot1Q].payload

    if debug:
        print("decap: VLAN stack ==", vlans[::-1])

    if ip_ver == 4:
        ip = p[IP]
        del ip.len
        del ip.chksum
    else:
        ip = p[IPv6]

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
    sendp(p, iface=me['iface'], verbose=1)
    if verbose:
        print(f"outbound: {p.summary()}")


def inbound(pkt):
    if verbose:
        print("[inbound]")
    p = decap(pkt)

    # layer-3 send() to forward the packet to the local process on the same host
    #
    if IP in p:
        sock_v4.send(p)  # , verbose=1)
    elif IPv6 in p:
        sock_v6.send(p)  # , verbose=1)
    else:
        pass  # ignore, pending extension

    if verbose:
        print(f"inbound: {p.summary()}")


def sniff_outbound():
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
    if 'ipv4' in me:
        print("IPv4 address:", me['ipv4'])
    if 'ipv6' in me:
        print("IPv6 address:", me['ipv6'])
    print("VLAN stack:", cf['qinq_vlans'])
    print()

    threading.Thread(target=sniff_outbound, daemon=True).start()
    threading.Thread(target=sniff_inbound,  daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[Tunnel stopped]")
