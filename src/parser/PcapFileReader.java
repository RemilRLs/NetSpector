package parser;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Map;
import java.util.HashMap;
import java.nio.charset.StandardCharsets;

public class PcapFileReader {

    private ArgumentParser argumentParser;
    private Map<String, TCPSession> tcpSessions = new HashMap<>();
    private Map<Integer, DNSPacket> dnsSessions = new HashMap<>();

    private Map<String, TCPStream> tcpStreams = new HashMap<>();

    private ByteOrder byteOrder; // To know if the file is in Big Endian or Little Endian.


    /**
     * Constructor for reading the Pcap file.
     * @param argumentParser the argument parser to know what the user wants to see when reading the PCAP file.
     */
    public PcapFileReader(ArgumentParser argumentParser) {
        this.argumentParser = argumentParser;
    }

    /**
     * Analyzes the PCAP file and check various network prootols
     * @param filePath the path to the PCAP file that I analyze.
     */

    public void analyzePcapFile(String filePath) {
        try(FileInputStream fileStream = new FileInputStream(filePath)) {

            // I check to be sure that the file is a PCAP file.
            if(!initializeGlobalHeaders(fileStream)) {
                return;
            }

            byte[] packetHeaderBytes = new byte[16];
            int packetCount = 0;

            while(fileStream.read(packetHeaderBytes) == packetHeaderBytes.length) {
                PacketHeader packetHeader = parsePacketHeader(packetHeaderBytes);

                ByteBuffer packetDataBuffer = readPacketData(fileStream, packetHeader);

                if(packetDataBuffer == null) {
                    System.err.printf("[X] - Error: Unable to read packet number %d\n", packetCount);
                    return;
                }

                processPacketOperation(packetDataBuffer);
                packetCount++;

            }

            showHttpStreams();
            showTcpStreams();

        } catch (FileNotFoundException e) {
            System.err.println("[X] - Error: File not found: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("[X] - Error: Unable to read the file: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("[X] - Error: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * Initialize global header link to the pcap file.
     * @param fileStream the FileInputStream link to the pcap file.
     * @return true if the file is valid, false not valid.
     * @throws IOException
     */

    private boolean initializeGlobalHeaders(FileInputStream fileStream) throws IOException {
        byte[] globalHeaderByte = new byte[24];

        if (fileStream.read(globalHeaderByte) != globalHeaderByte.length) {
            System.err.println("[X] - Error : File too small or error when opening/reading");
            return false;
        }

        ByteBuffer globalHeaderBuffer  = ByteBuffer.wrap(globalHeaderByte);
        GlobalHeader globalHeader = new GlobalHeader(globalHeaderBuffer);
        globalHeaderBuffer.order(ByteOrder.BIG_ENDIAN);

        // Checking if the magic number is a PCAP.
        if(globalHeader.getMagicNumber() == 0xA1B2C3D4) {
            System.out.println("[*] - Info : PCAP Magic Number in Big Endian detected");
            byteOrder = ByteOrder.BIG_ENDIAN;
        } else if(globalHeader.getMagicNumber() == 0xD4C3B2A1) {
            System.out.println("[*] - Info : PCAP Magic Number in Little Endian detected");
            byteOrder = ByteOrder.LITTLE_ENDIAN;

        } else {
            System.err.println("[X] - Error : Magic number unknown");
            return false;
        }

        globalHeaderBuffer.order(byteOrder);
        System.out.println(globalHeader);

        return true;
    }

    /**
     * Parse the packet header of each packet.
     * @param packetHeaderBytes byte link to the packet header (array of bytes)
     * @return the packet header.
     */
    private PacketHeader parsePacketHeader(byte[] packetHeaderBytes) {
        ByteBuffer packetHeaderBuffer = ByteBuffer.wrap(packetHeaderBytes);
        packetHeaderBuffer.order(byteOrder);

        PacketHeader packetHeader = new PacketHeader(packetHeaderBuffer);
        System.out.println(packetHeader);
        return packetHeader;
    }

    /**
     * Read the packet data of each packet.
     * @param fileStream the FileInputStream for reading packet data.
     * @param packetHeader to know the size of the packet data.
     * @return a Bytebuffer contening all the packet data
     * @throws IOException
     */
    private ByteBuffer readPacketData(FileInputStream fileStream, PacketHeader packetHeader) throws IOException {
        byte[] packetData = new byte[packetHeader.getIncLen()];

        if (fileStream.read(packetData) != packetHeader.getIncLen()) {
            System.err.println("[X] - Error : Unable to read the packet data");
            return null;
        }

        return ByteBuffer.wrap(packetData);
    }

    /**
     * Process ARP, IPv4, IPv6 packets.
      * @param data ByteBuffer containing the packet data.
     * @throws Exception
     */
    private void processPacketOperation(ByteBuffer data) throws Exception {
        EthernetHeader ethernetHeader = new EthernetHeader(data);
        System.out.println(ethernetHeader);

        int etherType = Short.toUnsignedInt(ethernetHeader.getEtherType());

        if(etherType == 0x0800) {
            if (argumentParser.isShowAllActivated() || argumentParser.isTCPActivated() || argumentParser.isUDPActivated() || argumentParser.isICMPActivated()) {
                processIPv4Packet(data);
            }
        } else if(etherType == 0x086DD) {
            if (argumentParser.isShowAllActivated() || argumentParser.isTCPActivated() || argumentParser.isUDPActivated() || argumentParser.isICMPActivated() || argumentParser.isQUICActivated()) {
                processIPv6Packet(data);
            }
        } else if(etherType == 0x0806) {
            if (argumentParser.isShowAllActivated() || argumentParser.isARPActivated()) {
                processARPPacket(data);
            }
        } else {
            System.out.println("[X] - Unknown Packet");
        }
    }

    /**
     * Process the IPv4 packet and protocol upper like TCP, UDP & ICMP.
     * @param packetDataBuffer ByteBuffer containing the packet data.
     * @throws Exception
     */
    private void processIPv4Packet(ByteBuffer packetDataBuffer) throws Exception {
        IPv4Packet ipv4Packet = new IPv4Packet(packetDataBuffer);
        System.out.println(ipv4Packet);

        int protocol = ipv4Packet.getUnsignedProtocolIdentifier();

        if ((argumentParser.isShowAllActivated() && protocol == 6) || (protocol == 6 && argumentParser.isTCPActivated())) { // TCP
            processTCPPacket(packetDataBuffer, ipv4Packet);
        }
        if ((argumentParser.isShowAllActivated() && protocol == 17) || (protocol == 17 && argumentParser.isUDPActivated())) { // UDP
            processUDPPacket(packetDataBuffer, ipv4Packet);
        }
        if ((argumentParser.isShowAllActivated() && protocol == 1)  || (protocol == 1 && argumentParser.isICMPActivated())) { // ICMPv4
            processICMPv4Packet(packetDataBuffer);
        }
    }

    /**
     * Process the IPv6 packet and protocol upper like TCP, UDP & ICMPv6.
     * @param packetDataBuffer ByteBuffer containing the packet data.
     * @throws Exception
     */

    private void processIPv6Packet(ByteBuffer packetDataBuffer) throws Exception {
        IPv6Packet ipv6Packet = new IPv6Packet(packetDataBuffer);
        System.out.println(ipv6Packet);

        int protocol = ipv6Packet.getUnsignedNextHeader();

        if ((argumentParser.isShowAllActivated() && protocol == 6) ||  (protocol == 6 && argumentParser.isTCPActivated())) { // TCP
            processTCPPacketIPv6(packetDataBuffer, ipv6Packet);
        }
        if ((argumentParser.isShowAllActivated() && protocol == 17) || (protocol == 17 &&  argumentParser.isUDPActivated())) { // UDP
            processUDPPacketIpv6(packetDataBuffer, ipv6Packet);
        }
        if ((argumentParser.isShowAllActivated() && protocol == 58) || (protocol == 58  && argumentParser.isICMPActivated())) { // ICMP
            processICMPv6Packet(packetDataBuffer);
        }
    }

    /**
     * Process the ARP packet.
     * @param packetDataBuffer ByteBuffer containing the packet data.
     */

    private void processARPPacket(ByteBuffer packetDataBuffer) {
        if(argumentParser.isARPActivated() || argumentParser.isShowAllActivated()) {
            ARPPacket arpPacket = new ARPPacket(packetDataBuffer);
            System.out.println(arpPacket);
        }
    }


    /**
     * Process the ICMPv4 packet.
     * @param packetDataBuffer ByteBuffer containing the packet data.
     */
    private void processICMPv4Packet(ByteBuffer packetDataBuffer) {
        ICMPv4Packet icmpv4Packet = new ICMPv4Packet(packetDataBuffer);
        System.out.println(icmpv4Packet);
    }

    /**
     * Process the ICMPv6 packet.
     * @param packetDataBuffer ByteBuffer containing the packet data.
     */

    private void processICMPv6Packet(ByteBuffer packetDataBuffer) {
        ICMPv6Packet icmpv6Packet = new ICMPv6Packet(packetDataBuffer);
        System.out.println(icmpv6Packet);
    }

    /**
     * Process the UDP packet and protocol upper like DHCP, DNS & QUIC.
     * @param packetDataBuffer ByteBuffer containing the packet data.
     * @param ipv4packet the IPv4 packet link to the DHCP, DNS & QUIC packet.
     * @throws Exception
     */


    private void processUDPPacket(ByteBuffer packetDataBuffer, IPv4Packet ipv4packet) throws Exception {
        UDPacket udpPacket = new UDPacket(packetDataBuffer);
        System.out.println(udpPacket);

        if (((argumentParser.isShowAllActivated() && isValidDHCPPacket(udpPacket.getData())) || (argumentParser.isDHCPActivated()) && isValidDHCPPacket(udpPacket.getData()))) {
            processDHCPPacket(udpPacket.getData());
        }

        if (((argumentParser.isShowAllActivated() && isValidDNSPacket(udpPacket.getData()) ||(argumentParser.isDNSActivated()) && isValidDNSPacket(udpPacket.getData())))) {
            processDNSPacket(udpPacket.getData());
        }

        if (((argumentParser.isShowAllActivated() && isQuicProtocol(udpPacket.getData()) || (argumentParser.isQUICActivated()) && isQuicProtocol(udpPacket.getData())))) {
            processQuicPacket(udpPacket.getData());

        }
    }

    /**
     * Process the UDP packet for IPv6 and protocol upper like DHCP, DNS & QUIC.
     * @param packetDataBuffer ByteBuffer containing the packet data.
     * @param ipv6packet the IPv6 packet link to the DHCP, DNS & QUIC packet.
     * @throws Exception
     */

    private void processUDPPacketIpv6(ByteBuffer packetDataBuffer, IPv6Packet ipv6packet) throws Exception {
        UDPacket udpPacket = new UDPacket(packetDataBuffer);
        System.out.println(udpPacket);

        if (((argumentParser.isShowAllActivated() && isValidDHCPPacket(udpPacket.getData())) || (argumentParser.isDHCPActivated() && isValidDHCPPacket(udpPacket.getData())))) {
            processDHCPPacket(udpPacket.getData());
        }

        if (((argumentParser.isShowAllActivated() && isValidDNSPacket(udpPacket.getData())) || (argumentParser.isDNSActivated() && isValidDNSPacket(udpPacket.getData())))) {
            processDNSPacket(udpPacket.getData());
        }

        if (((argumentParser.isShowAllActivated() && isQuicProtocol(udpPacket.getData())) || (argumentParser.isQUICActivated() && isQuicProtocol(udpPacket.getData())))) {
            processQuicPacket(udpPacket.getData());
        }
    }

    /**
     * Generate a stream key to identify the TCP stream.
     * @param ip1 for the first host
     * @param port1 port of the first host
     * @param ip2  for the second host
     * @param port2  port of the second host
     * @return a unique key.
     */
    private String generateStreamKey(String ip1, int port1, String ip2, int port2) {
        if (ip1.compareTo(ip2) < 0 || (ip1.equals(ip2) && port1 <= port2)) {
            return ip1 + ":" + port1 + "-" + ip2 + ":" + port2;
        } else {
            return ip2 + ":" + port2 + "-" + ip1 + ":" + port1;
        }
    }

    /**
     * Process the TCP packet.
     * @param packetDataBuffer ByteBuffer containing the packet data.
     * @param ipv4Packet the IPv4 packet link to the TCP packet.
     */

    private void processTCPPacket(ByteBuffer packetDataBuffer, IPv4Packet ipv4Packet) {
        TCPacket tcpPacket = new TCPacket(packetDataBuffer);
        System.out.println(tcpPacket);

        String sourceIP = ipv4Packet.getSourceAddress();
        String destinationIP = ipv4Packet.getDestinationAddress();
        int sourcePort = tcpPacket.getSourcePort();
        int destPort = tcpPacket.getDestPort();

        /**
         * I'm creating a birectional stream key to identify the TCP stream.
         */
        String streamKey = generateStreamKey(sourceIP, sourcePort, destinationIP, destPort);

        /**
         * I'm creating a TCP stream specific to a session thanks to streamKey if that one
         * doesn't exist yet I create a new TCP Stream
         */
        TCPStream stream = tcpStreams.getOrDefault(streamKey,
                new TCPStream(sourceIP, destinationIP, sourcePort, destPort));


        stream.addDataSegment(sourceIP, sourcePort, tcpPacket.getSequenceNumber(), tcpPacket.getData());
        tcpStreams.put(streamKey, stream); // I put the TCP Stream inside the map list link to the streamKey.

        // That for FTP.
        if(tcpPacket.getData() != null && (argumentParser.isFTPActivated() || argumentParser.isShowAllActivated())) {
            ByteBuffer tcpDataBuffer = tcpPacket.getDataBuffer();
            String rawData = new String(tcpDataBuffer.array(), StandardCharsets.US_ASCII);

            String ftpCommand = detectAndExtractFTPCommand(rawData); // I get the command FTP.

            if(ftpCommand != null){
                FTPPacket ftpPacket = new FTPPacket(tcpDataBuffer, ftpCommand, false);
                System.out.println(ftpPacket);
            } else if(detectFTPResponse(rawData)) {
                FTPPacket ftpPacket = new FTPPacket(tcpDataBuffer, null, true);
                System.out.println(ftpPacket);
            }
        }
    }

    /**
     * Process the QUIC packet.
     * @param data byte array containing the packet data.
     */

    private void processQuicPacket(byte[] data) {
        QuicPacket quicPacket = new QuicPacket(data);
        System.out.println(quicPacket);

    }

    /**
     * Check if the packet is QUIC protocol
     * @param data byte array containing the packet data.
     * @return
     */

    private boolean isQuicProtocol(byte[] data) {
        byte firstByte = data[0];
        boolean isLongHeader = (firstByte & 0x80) != 0;


        if (isLongHeader) {
            if (data.length < 6) { // Minimal size of a QUICT long header.
                return false;
            }

            return true;
        } else {
            // To difficult to read the short header :( maybe if I had more time
            return false;
        }
    }

    /**
     * Process the TCP packet for IPv6.
     * @param packetDataBuffer ByteBuffer containing the packet data.
     * @param iPv6Packet the IPv6 packet link to the TCP packet.
     */

    private void processTCPPacketIPv6(ByteBuffer packetDataBuffer, IPv6Packet iPv6Packet) {
        TCPacket tcpPacket = new TCPacket(packetDataBuffer);
        System.out.println(tcpPacket);


        String sourceIP = iPv6Packet.getSourceAddress();
        String destinationIP = iPv6Packet.getDestinationAddress();
        int sourcePort = tcpPacket.getSourcePort();
        int destPort = tcpPacket.getDestPort();


        // Me key session to retrieve the session (bidirectional)

        String streamKey = generateStreamKey(sourceIP, sourcePort, destinationIP, destPort);

        TCPStream stream = tcpStreams.getOrDefault(streamKey,
                new TCPStream(sourceIP, destinationIP, sourcePort, destPort));

        // Is there a session already created? :)

        stream.addDataSegment(sourceIP, sourcePort, tcpPacket.getSequenceNumber(), tcpPacket.getData());
        tcpStreams.put(streamKey, stream);


        if(tcpPacket.getData() != null && argumentParser.isFTPActivated()) {
            ByteBuffer tcpDataBuffer = tcpPacket.getDataBuffer();
            String rawData = new String(tcpDataBuffer.array(), StandardCharsets.US_ASCII);

            String ftpCommand = detectAndExtractFTPCommand(rawData); // I get the command FTP.

            if(ftpCommand != null){
                FTPPacket ftpPacket = new FTPPacket(tcpDataBuffer, ftpCommand, false);
                System.out.println(ftpPacket);
            } else if(detectFTPResponse(rawData)) {
                FTPPacket ftpPacket = new FTPPacket(tcpDataBuffer, null, true);
                System.out.println(ftpPacket);
            }
        }
    }

    /**
     * Process the DNS packet.
     * @param data byte array containing the packet data.
     */

    private void processDNSPacket(byte[] data) {
        ByteBuffer dnsBuffer = ByteBuffer.wrap(data);
        DNSPacket dnsPacket = new DNSPacket(dnsBuffer);
        System.out.println(dnsPacket);

        if (!dnsPacket.isResponse()) { // If it is a query.
            dnsSessions.put(dnsPacket.getTransactionId(), dnsPacket);
        } else {
            DNSPacket query = dnsSessions.get(dnsPacket.getTransactionId());
            if (query != null) { // Answer about the query.
                System.out.println("DNS Response found for query ID: " + dnsPacket.getTransactionId());
                System.out.println("----- Query -----");
                System.out.println(query);
                System.out.println("----- Response -----");
                System.out.println(dnsPacket);

                dnsSessions.remove(dnsPacket.getTransactionId());
            }
        }
    }

    /**
     * Detect and extract the FTP command from the data.
     * @param rawData the data from the segment TCP.
     * @return the FTP command.
     */

    private String detectAndExtractFTPCommand(String rawData) {
        String[] ftpCommands = {"USER", "PASS", "STOR", "RETR", "LIST", "QUIT", "PORT", "PASV", "MKD", "RMD", "TYPE", "CWD", "PWD", "SYST", "FEAT", "SIZE", "MDTM", "REST", "ABOR", "DELE", "RNFR", "RNTO", "APPE", "NLST", "STAT", "HELP", "NOOP"};
        for (String command : ftpCommands) {
            if (rawData.startsWith(command)) {
                return command;
            }
        }
        return null; // If there is no command FTP inside the data from the segment TCP.

    }


    /**
     * Detect if the data is a FTP response.
     * @param data the data from the segment TCP.
     * @return true if it is a FTP response, false if it is not.
     */
    private boolean detectFTPResponse(String data) {
        // https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes
        if(data.length() >= 3){
            try {
                int code = Integer.parseInt(data.substring(0, 3));

                if (code >= 100 && code <= 600) {
                    return true;
                }
            }
            catch (NumberFormatException e) { // Needed that because sometime it is not a valid number.
                return false;
            }
        }


        return false;
    }

    /**
     * Check if the DNS packet is valid packet DNS.
     * @param data byte array containing the packet data.
     * @return true if it is a valid DNS packet, false if it is not.
     */

    private boolean isValidDNSPacket(byte[] data) {
        // https://en.wikipedia.org/wiki/Domain_Name_System#:~:text=DNS%20message%20format,-The%20DNS%20protocol&text=Each%20message%20consists%20of%20a,content%20of%20these%20four%20sections.&text=Response%20code%2C%20can%20be%20NOERROR,%2C%20Nonexistent%20domain)%2C%20etc.
        // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
        // My god that one...

        if(data.length < 12) {
            return false;
        }

        if (data.length >= 12) {
            ByteBuffer dnsBuffer = ByteBuffer.wrap(data);
            dnsBuffer.order(ByteOrder.BIG_ENDIAN); // LOL Why it only in big endian. I think it's because TCP is in big endian by default.


            int originalPosition = dnsBuffer.position();
            try {
                int transactionID = Short.toUnsignedInt(dnsBuffer.getShort()); // AAAAAAAAAAA Whyyy I had to read that first
                int flags = Short.toUnsignedInt(dnsBuffer.getShort());

                int qrFlag = (flags >> 15) & 0x01;
                int opcode = (flags >> 11) & 0x0F;
                int responseCode = flags & 0x000F;

                // Validate opcode and response code
                if (opcode > 15 || responseCode > 15) { // opcode can't be superor to 3 and response code can't be superior to 5. I had to change the responseCode to 15 because I didn't have all the DNS query/response...
                    return false;
                }

                int questionCount = Short.toUnsignedInt(dnsBuffer.getShort());
                int answerCount = Short.toUnsignedInt(dnsBuffer.getShort());
                int authorityCount = Short.toUnsignedInt(dnsBuffer.getShort());
                int additionalCount = Short.toUnsignedInt(dnsBuffer.getShort());


                // Needed that to fix QUIC that was detected as DNS. I know that not the best way...
                if (questionCount > 50 || answerCount > 50 || authorityCount > 50 || additionalCount > 50) {
                    return false;
                }
                // The qrFlag allow me to know if it is a query or a response. if it's a response it will be equal to 1 but if it's a query it will be equal to 0 and so it can't be possible to have a qrFlag == 1 and answerCount == 0.
                if (questionCount == 0) {
                    return false;
                }

                return true;


            } catch (Exception e) {
                dnsBuffer.position(originalPosition);
                return false;
            }

        }
            return false;
    }

    /**
     * Check if the DHCP packet is valid packet DHCP.
     * @param data byte array containing the packet data.
     * @return true if it is a valid DHCP packet, false if it is not.
     */

    private boolean isValidDHCPPacket(byte[] data){
        // https://support.hpe.com/techhub/eginfolib/networking/docs/switches/5120si/cg/5998-8491_l3-ip-svcs_cg/content/436042653.htm

        if(data.length >= 240) {
            ByteBuffer dhcpBuffer = ByteBuffer.wrap(data);
            dhcpBuffer.order(ByteOrder.BIG_ENDIAN); // Same heeere.

            int originalPosition = dhcpBuffer.position();
            try {
                int op = Byte.toUnsignedInt(dhcpBuffer.get());
                if (op != 1 && op != 2) {
                    return false;
                }
                dhcpBuffer.position(originalPosition + 236);
                int magicCookie = dhcpBuffer.getInt();
                return magicCookie == 0x63825363;
            } catch (Exception e) {
                dhcpBuffer.position(originalPosition);
                return false;
            }
        }
        return false;
    }

    /**
     * Process the DHCP packet.
     * @param data byte array containing the packet data.
     * @throws Exception
     */
    private void processDHCPPacket(byte[] data) throws Exception {
        ByteBuffer dhcpBuffer = ByteBuffer.wrap(data);
        DHCPPacketG dhcpPacket = new DHCPPacketG(dhcpBuffer);
        System.out.println(dhcpPacket);
    }

    /**
     * Display ! the HTTP streams.
     */
    private void showHttpStreams() {
        if(!argumentParser.isHTTPActivated() && !argumentParser.isShowAllActivated()) {
            return;
        }

        if(tcpStreams.isEmpty()) {
            System.out.println("[+] - Info: No HTTP Stream found");
            return;
        }

        String specificKey = argumentParser.getSpecificHttpSessionKey();

        // HTTP Follow Stream.

        if(specificKey != null && tcpStreams.containsKey(specificKey)) {
            TCPStream  stream = tcpStreams.get(specificKey);

            if (stream.isHTTP()) {
                System.out.println("HTTP Stream found: " + specificKey);
                System.out.println(stream.getFullData());
                System.out.println("\n------------------------\n");
            } else {
                System.out.println("[X] - No HTTP Stream Found for the specified key that you gave : " + specificKey);
            }

        } else if (specificKey == null) { // HTTP all Stream that I show.
            System.out.println("\n------------------------\nHTTP Streams\n------------------------\n");
            for (Map.Entry<String, TCPStream> entry : tcpStreams.entrySet()) { // I go through every HTTP Session
                TCPStream stream = entry.getValue();
                if (stream.isHTTP()) {
                    System.out.println("HTTP Stream found: " + entry.getKey());
                    System.out.println(stream.getFullData());
                    System.out.println("\n------------------------\n");
                }
            }
        } else {
            System.out.println("[X] - No HTTP Stream Found for the specified key that you gave : " + specificKey);
        }


    }

    /**
     * That the same as HTTP stream but for TCP now.
     */
    private void showTcpStreams() {
        if (!argumentParser.isTCPActivated() && !argumentParser.isShowAllActivated()) {
            return;
        }

        if (tcpStreams.isEmpty()) {
            System.out.println("[+] - Info: No TCP Stream found");
            return;
        }

        String specificTcpKey = argumentParser.getSpecificTcpStreamKey();

        if (specificTcpKey != null && tcpStreams.containsKey(specificTcpKey)) {
            System.out.println("\n------------------------\nSpecfic TCP Stream found\n------------------------\n");
            TCPStream stream = tcpStreams.get(specificTcpKey);
            displayTcpStream(specificTcpKey, stream);
        } else if (specificTcpKey == null) {
            System.out.println("\n------------------------\nTCP Streams\n------------------------\n");
            for (Map.Entry<String, TCPStream> entry : tcpStreams.entrySet()) {
                displayTcpStream(entry.getKey(), entry.getValue());
            }
        } else {
            System.out.println("[X] - No TCP Stream Found for the specified key that you gave: " + specificTcpKey);
        }
    }

    private void displayTcpStream(String streamKey, TCPStream stream) {
        System.out.println("TCP Stream: " + streamKey);
        System.out.println(stream.getFullData());
        System.out.println("\n------------------------\n");
    }



}

