# NetSpector

## Description

NetSpector is a command-line tool for analyzing files
PCAP in order to extract information on various network protocols such as:

* QUIC
* HTTP (with follow stream)
* FTP
* DNS (with follow Query & Response)
* DHCP
* TCP (with follow stream)
* UDP
* ARP
* ICMPv4 & ICMPv6
* IPv4 & IPv6
* Ethernet

NetSpector can allow you to examine specific TCP flows and filter through option
protocols.

## Main functionality

* Support for a multitude of protocols
* TCP & HTTP flow monitoring
* DNS query tracking
* Advanced protocol filtering
* Bidirectional flow reconstruction for TCP/HTTP/DNS to capture complete exchanges between client and server.

## Difficulties encountered

* The bit shifting operations was challenging especially when dealing with header fields that required some specific mainipulation like when a field what only one byte. For example
* doing DNS and TCP headers where pretty much challenging to extract data.
* It was'nt clear that some fields needed to be trated as unsigned integers that led me to some incorrect values and bug when processing for example IPv4 and IPv6 packet.
* Handling with headers (like next header in IPv6) that change was tricky. For example, in IPv6 each type of next header can vary in size such as the Fragment Header and Routing Header
* The DNS protocol presented unique challenges because of the way the packet header is. Also to know if it's a DNS packet or not what so hard to determine.
* TCP Stream was particularly challenging to manage for example birectional communication to know if it's an answer or a request.  
* I had to understand clearly how every protocol works and how to extract data from it so read a lot of document like RFC / Wikipedia / Stackoverflow / Wireshark documentation and more...
* Difficulty working with QUIC short headers

## Compilation 

To compile the project you just have to follow the following steps:

```bash
javac -d out -sourcepath src src/main/NetSpector.java
```

## Running the project

```bash
java -cp out main.NetSpector [options]
```

## Using NetSpector

To use NetSpector, simply run the following command:


```bash
java main.NetSpector -f <file.pcap> [options]
```

### Example of use


1 - Analyze an entire PCAP file:


```bash
java main.NetSpector -f example.pcap --showall
```

2 - Show only TCP packets
 

```bash
java main.NetSpector -f example.pcap --tcp
```

Precision: Will display all TCP flows and information on each TCP packet.


3 - Follow a specific TCP flow


```bash
java main.NetSpector -f example.pcap --tcp --tcpStream="192.168.1.1:50863-192.168.1.2:80"
```

Allows you to follow a specific TCP flow between the source IP address and the destination IP address and vice versa.


4 - Follow HTTP Stream

```bash
java main.NetSpector -f example.pcap --http --httpKey="192.168.1.2:80 -> 192.168.1.1:50000"
```

Allows you to follow an HTTP flow between the source IP address and the destination IP address.

5 - Viewing DNS Queries


```bash
java main.NetSpector -f example.pcap --dns
```

## Options

| Option              | Description                                                                                           |
|---------------------|-------------------------------------------------------------------------------------------------------|
| `-f <file>`         | Specifies the PCAP file to analyze. This parameter is required.                                       |
| `--tcp`             | Displays only TCP packets.                                                                            |
| `--udp`             | Displays only UDP packets.                                                                            |
| `--dns`             | Displays only DNS packets and automatically activates `--udp`.                                        |
| `--dhcp`            | Displays only DHCP packets and automatically activates `--udp`.                                       |
| `--ftp`             | Displays only FTP packets.                                                                            |
| `--arp`             | Displays only ARP packets.                                                                            |
| `--icmp`            | Displays only ICMP packets.                                                                           |
| `--ipv4`            | Displays only IPv4 packets.                                                                           |
| `--ipv6`            | Displays only IPv6 packets.                                                                           |
| `--quic`            | Displays only QUIC packets.                                                                           |
| `--http`            | Displays only HTTP packets                                                                            |
| `--httpKey=<key>`   | Specifies the key for a specific HTTP session, example :  `192.168.1.2:80 -> 192.168.1.1:50000`.      |
| `--tcpStream=<key>` | Specifies the key for a specific TCP stream to follow, example :  `192.168.1.1:50863-192.168.1.2:80`. |
| `--showall`         | Displays all packets, so all protocols.                                                               |
| `-h`, `--help`      | Displays all available options and commands.                                                          |
