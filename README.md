# qinq v1.0 [20251114]

Script to bridge end hosts over QinQ

by Terence LEE <telee.hk@gmail.com>

https://github.com/telee0/poc_scripts

https://scapy.net

## Tested with IP/TCP/UDP/ICMP

Destination MAC is always required so we have a database in the script to keep host details.

```
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
}
```

Scapy is required to manipluate packets

```
$ pip freeze
scapy==2.6.1
setuptools==80.9.0
wheel==0.45.1
```
