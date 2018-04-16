`-A` shows plain text packet information being sent

Tcpdump is an extremley useful command for troubleshooting connectivity. I am including notes on some basic functionality of the command. These were mainly sourced from the man page and this wonderful [site](http://bencane.com/2014/10/13/quick-and-practical-reference-for-tcpdump/).

## Flag Usage
* Don't translate hostnames, ports, etc... By default tcpdump will attempt to lookup and translate IPs to hostnames. It does this with ports too.
```
tcpdump -n
```

* Add verbosity to tcpdump; tcpdump has three verbosity levels, you can add more verbosity by adding additional v's to the command line flags.
```
tcpdump -v
```

* Specify an interface to trace (dump) from. By default when you run tcpdump without specifying an interface it will choose the lowest numbered interface, usually this is eth0 however that is not guaranteed for all systems.
```
tcpdump -i eth0
```

> If you want to capture from all interfaces this can be accomplished with `any`.
```
tcpdump -i any
```

* Save the output of tcpdump to a file. By default the data is buffered and will not usually be written to the file until you CTRL+C out of the running tcpdump command.
```
tcpdump -w /var/tmp/output.pcap
```

* Read from a file. This is the counterpart to the above command.
```
tcpdump -r /path/to/file
```
* Specify the capture size of a packet.
```
tcpdump -s 100
```
> By default most newer implementations of tcpdump will capture 65535 bytes.
* Specify the number of packets to capture. This is very useful as tcpdump will continue to run until you `CTRL+C` out of it.
```
tcpdump -c 10
```

Here is an example command with several of the above flags. This will not attempt to translate IPs to hostnames, provide the maximum verbosity, listen to any interface, capture only 100 packets, and capture packets with a snapshot length of 100.
```
tcpdump -nvvv -i any -c 100 -s 100
```

### Getting Granular
If we only want to capture packets that are sent or recieved from a particular IP we can accomplish this with the `host` filter.
* Look for 10 packets on any interface that were sent or recieved from 10.0.0.15.
```
tcpdump -nvvv -i any -c 10 host 10.0.0.15
```

* Capture packets from 10.0.0.15 only if it is the source.
```
tcpdump -nvvv -i any -c 10 src host 10.0.0.15
```
> `src` is used for specifying a source filter on `host` and `dst` is for specifying a destination.

* Only show packets that have both ports 22 and 60738.
```
tcpdump -nvvv -i any -c 3 port 22 and port 60738
```
> `and` and `&&` are the same to tcpdump but be aware that `&&` is also valid bash and will need to be wrapped in quotes so bash doesn't recognize it.
```
tcpdump -nvvv -i any -c 3 'port 22 && port 60738'
```
* Show traffic on one port or another.
```
tcpdump -nvvv -i any -c 20 'port 80 or port 443'
```
> `or` and `||` are the same to tcpdump but be aware that `||` is also valid bash and will need to be wrapped in quotes so bash doesn't recognize it.
* Specify two specific ports and look for packets fromm a specific host.
```
tcpdump -nvvv -i any -c 20 '(port 80 or port 443) and host 10.0.0.15'
```
* Look for packets over port 80 and 443, from two hosts, that are destined for 10.0.0.15
```
tcpdump -nvvv -i any -c 20 '((port 80 or port 443) and (host 10.0.100.1 or host 10.0.0.16)) and dst host 10.0.0.15'
```
