# RudScan - A Rudimentary Network Scanner

RudScan can scan hosts in your network to find if they are up and what ports they are listening on. 

## Usage
```bash
$ make 

$ rudscan
usage: rudscan <cidr>


```

## Examples
```bash
# scan for open ports on your local machine
$ rudscan 127.0.0.1/32

# scan for online hosts and their open ports on a class D subnet
$ rudscan 172.24.16.31/24 # a 24-bit mask
```

# Working

# Ping Scan
A little bit about the ICMP protocol: 
The ICMP protocol is a simple protocol built on top of the Internet Protocol. It is generally used to get feedback about problems in the network. 

```
 0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Data ...
   +-+-+-+-+-
```
The format of an ICMP echo message.

To figure out if a host is up, we can send an ICMP ECHO request (icmp_type: 8) to the host, if the host responds with an ICMP ECHO response (icmp_type: 0). In other cases, we may receive an ICMP Destination Unreachable or no response at all (in this case we simply timeout). Thus, we can mark all active hosts in the network using the ICMP protocol. 

## Note about Privileges
Since ICMP is built over IP, we need to use raw sockets to be able to send ICMP packets. *NIX systems only allow the root user to open raw sockets. To work around this with minimum privileges, we compile rudscan as a setuid binary. 

## Caveats
- Some hosts intentionally ignore ICMP Echo requests. This is usually an OS level option that can be set by the owner. Due to this, we might miss some hosts that were online but could did not respond to our probes. 


# Scanning for Open Ports
Once we have determined that a host is up, we can proceed to scan for open ports on the host. For this, we perform a TCP scan and then a UDP scan.

## TCP Scan
We use the TCP `connect()` syscall to determine if a port is open. If the connect call succeeds before a set timeout, we can assume that it is up. If we get an `ECONNREFUSED`, or a timeout, we assume that the port is not listening for connections and move on. To improve performance of the scan, we use non blocking sockets in combination with the `select()` syscall.

### Caveats
- When scanning for ports on your local machine, you might see some garbage values. This is because a connection on a closed ephemeral port has a small chance of connecting to itself with a 4-way or "split" handshake.

## UDP Scan
For the UDP port scan, we assume that all ports are open. Next, we open a raw socket. We use this raw socket to send a datagram on each of the 65536 ports on the host. If the port is closed, the kernel will send an ICMP Destination Unreachable response message. On receiving this message, we can assume that the port is closed. 

### Caveats
- Sometimes the kernel might not send an ICMP packet. In this case, we would be unable to determine that the port is open or closed.
- To ensure that we have received all ICMP packets from the host, we wait for N RTTs from the host. To do this, we randomly select a closed port and send a packet to it.
