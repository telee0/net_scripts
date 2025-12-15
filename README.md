# qinq v2.0 [20251215]

Script to bridge end hosts over QinQ

by Terence LEE <telee.hk@gmail.com>

https://github.com/telee0/poc_scripts

https://scapy.net

### Tested with IPv4/IPv6/TCP/UDP/ICMP

Destination MAC is always required so we have a database in the script to keep host details.

```
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
```

Scapy is required to manipluate packets

```
$ pip freeze
scapy==2.6.1
setuptools==80.9.0
wheel==0.45.1
```

Sample test results

```
ubuntu-236:

$ ping -6 -c 10 2001::237
(base) terence@ubuntu-236:~$ ping -6 -c 10 2001::237
PING 2001::237(2001::237) 56 data bytes
64 bytes from 2001::237: icmp_seq=1 ttl=64 time=38.7 ms
64 bytes from 2001::237: icmp_seq=2 ttl=64 time=37.1 ms
64 bytes from 2001::237: icmp_seq=3 ttl=64 time=38.4 ms
64 bytes from 2001::237: icmp_seq=4 ttl=64 time=40.7 ms
64 bytes from 2001::237: icmp_seq=5 ttl=64 time=31.7 ms
64 bytes from 2001::237: icmp_seq=6 ttl=64 time=38.5 ms
64 bytes from 2001::237: icmp_seq=7 ttl=64 time=41.6 ms
64 bytes from 2001::237: icmp_seq=8 ttl=64 time=40.9 ms
64 bytes from 2001::237: icmp_seq=9 ttl=64 time=39.4 ms
64 bytes from 2001::237: icmp_seq=10 ttl=64 time=37.2 ms

--- 2001::237 ping statistics ---
10 packets transmitted, 10 received, 0% packet loss, time 9009ms
rtt min/avg/max/mdev = 31.677/38.422/41.553/2.657 ms
(base) terence@ubuntu-236:~$ 

(base) terence@ubuntu-236:~$ iperf3 -6 -c 2001::237 -u
Connecting to host 2001::237, port 5201
[  5] local 2001::236 port 38435 connected to 2001::237 port 5201
[ ID] Interval           Transfer     Bitrate         Total Datagrams
[  5]   0.00-1.00   sec   134 KBytes  1.10 Mbits/sec  15  
[  5]   1.00-2.00   sec   125 KBytes  1.02 Mbits/sec  14  
[  5]   2.00-3.00   sec   125 KBytes  1.02 Mbits/sec  14  
[  5]   3.00-4.00   sec   134 KBytes  1.10 Mbits/sec  15  
[  5]   4.00-5.00   sec   125 KBytes  1.02 Mbits/sec  14  
[  5]   5.00-6.00   sec   125 KBytes  1.02 Mbits/sec  14  
[  5]   6.00-7.00   sec   134 KBytes  1.10 Mbits/sec  15  
[  5]   7.00-8.00   sec   125 KBytes  1.02 Mbits/sec  14  
[  5]   8.00-9.00   sec   125 KBytes  1.02 Mbits/sec  14  
[  5]   9.00-10.00  sec   134 KBytes  1.10 Mbits/sec  15  
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-10.00  sec  1.26 MBytes  1.05 Mbits/sec  0.000 ms  0/144 (0%)  sender
[  5]   0.00-10.11  sec  0.00 Bytes  0.00 bits/sec  0.000 ms  0/0 (0%)  receiver

iperf Done.
(base) terence@ubuntu-236:~$ 
(base) terence@ubuntu-236:~$ curl http://[2001::237]:8000
<!DOCTYPE HTML>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Directory listing for /</title>
</head>
<body>
<h1>Directory listing for /</h1>
<hr>
<ul>
<li><a href=".bash_history">.bash_history</a></li>
<li><a href=".bash_logout">.bash_logout</a></li>
<li><a href=".bashrc">.bashrc</a></li>
<li><a href=".cache/">.cache/</a></li>
<li><a href=".conda/">.conda/</a></li>
<li><a href=".config/">.config/</a></li>
<li><a href=".exrc">.exrc</a></li>
<li><a href=".profile">.profile</a></li>
<li><a href=".ssh/">.ssh/</a></li>
<li><a href=".sudo_as_admin_successful">.sudo_as_admin_successful</a></li>
<li><a href=".viminfo">.viminfo</a></li>
<li><a href="bin/">bin/</a></li>
<li><a href="Downloads/">Downloads/</a></li>
<li><a href="miniconda3/">miniconda3/</a></li>
</ul>
<hr>
</body>
</html>
(base) terence@ubuntu-236:~$ 


ubuntu-237:

$ iperf3 -s -6
$ python -m http.server --bind :: 8000

```


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
