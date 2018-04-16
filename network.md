## Commands
---
### mtr
* `-n` or `--no-dns`

Use this option to force mtr to display numeric IP numbers and not try to resolve the host names.

* `-r` or `--report`

This option puts mtr into report mode.  When in this mode, mtr will run for the number of cycles specified by the -c option, and then print statistics and exit.

This  mode is useful for generating statistics about network quality.  Note that each running instance of mtr generates a significant amount of network traffic.  Using mtr to measure the quality of your network may result in decreased network performance.

* `-c COUNT` or `--report-cycles COUNT` where COUNT equals number of interations

Use this option to set the number of pings sent to determine both the machines on the network and the reliability of those machines.  Each cycle lasts one second.

* `-4` or `-6`
Use this option to specify IPv4 or IPv6

> Example
```
# mtr -4 -n -r -c 15 google.com
# HOST: chrisdlg.com                Loss%   Snt   Last   Avg  Best  Wrst StDev
  1.|-- 23.253.124.3               0.0%    15    3.1   3.2   3.0   4.0   0.0
  2.|-- 98.129.84.160              0.0%    15    3.2   3.1   3.0   3.2   0.0
  3.|-- 74.205.108.48              0.0%    15    3.0   3.1   2.9   3.8   0.0
  4.|-- 74.205.108.120             0.0%    15    3.1   3.0   3.0   3.2   0.0
  5.|-- 10.25.1.119                0.0%    15    6.0   6.2   5.8   9.3   0.8
  6.|-- 72.14.221.26               0.0%    15    5.9   5.8   4.2   6.2   0.5
  7.|-- ???                       100.0    15    0.0   0.0   0.0   0.0   0.0
  8.|-- 108.170.226.109            0.0%    15    5.9   6.1   5.8   6.4   0.0
  9.|-- 172.217.12.78              0.0%    15    6.0   5.7   3.7   6.4   0.6
```
---
### nmcli
* Show all connections

```
# nmcli con show

Shorthand
# nmcli c s
```

* Get interface details

```
# nmcli con show eth0
```

* Add or remove an IP from an interface

```
Add IP
# nmcli con mod <INTERFACE> +ipv4.address "<IP>/<NETMASK>"

Remove IP
# nmcli con mod <INTERFACE> -ipv4.address "<IP>/<NETMASK>"
```
