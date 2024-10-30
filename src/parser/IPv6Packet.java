package parser;

import static parser.PacketUtils.bytesToIPv6;

// https://www.geeksforgeeks.org/internet-protocol-version-6-ipv6-header/

import java.nio.ByteBuffer;

public class IPv6Packet {
    private byte version; // 6.
    private byte PriorityTrafficClass; // Priority of the packet useful for the router.
    private int flowLabel; // Identify a path for the packet for special treatment.
    private short payloadLength; // Size of the data encapsulated inside the IPv6 Header.
    private byte nextHeader; // Indicate the protocol of the upper
    private byte hopLimit; // Time to live.
    private byte[] sourceAddress = new byte[16]; // 16 bytes IPv6 source address.
    private byte[] destinationAddress = new byte[16]; // 16 bytes IPv6 destination address.

    /**
     * Constructor allowing to retrieve and initialize IPv6 Header values
     * @param buffer ByteBuffer to get information from the IPv6 Header.
     */
    public IPv6Packet(ByteBuffer buffer) {
        int readFirstLine = buffer.getInt(); // 32 bits : 4 octets
        this.version = (byte) ((readFirstLine >> 28) & 0x0F); // I extract only the last 4 bytes which contain the version.
        /**
         * 0110 1111 0101 1100 0010 0011 0100 0000
         * >> 20 : 0000 0000 0000 0000 0000 0110 1111 0101 | I want 1111 0101
         */
        this.PriorityTrafficClass = (byte) ((readFirstLine >> 20) & 0xFF); // Mask And Bit to bit 1111 1111 I get 1111 0101
        this.flowLabel = readFirstLine & 0xFFFFF; // 20 last bytes.
        this.payloadLength = buffer.getShort();
        this.nextHeader = buffer.get();
        this.hopLimit = buffer.get();
        buffer.get(sourceAddress);
        buffer.get(destinationAddress);

        useIPv6NextHeader(buffer, this.nextHeader); // Check if there is more to see in the nextHeader.
    }


    /**
     * Get the source address of the IPv6 packet.
     * @return String representation of the source address.
     */
    public String getSourceAddress() {
        return bytesToIPv6(sourceAddress);
    }

    /**
     * Same but for destination.
     * @return String representation of the destination address.
     */

    public String getDestinationAddress() {
        return bytesToIPv6(destinationAddress);
    }

    /**
     * Function to check the nextHeader and see if there is more to see.
     * If there is it will call the function again but I don't look anything into the next header because I don't need it (I jump).
     * @param buffer ByteBuffer to get information from the IPv6 Header.
     * @param nextHeader Next Header to check.
     */

    private void useIPv6NextHeader(ByteBuffer buffer, byte nextHeader) {
        // https://en.wikipedia.org/wiki/IPv6_packet
        // https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        // https://datatracker.ietf.org/doc/rfc8754/

        while(true){
            switch(nextHeader & 0xFF) {
                case 0: // Hop-by-Hop Option that need to be examined by all device that the packet go through.
                    System.out.println("\n[!] Info : - Hop-by-Hop header found\n");
                    nextHeader = readNextHeader(buffer, nextHeader);
                    if (this.nextHeader == -1) return;
                    break;
                case 43:
                    System.out.println("\n[!] Info : - Routing header found\n"); // Specifiy the route of the packet.
                    nextHeader = readNextHeader(buffer, nextHeader);
                    if (nextHeader == -1) return;
                    break;
                case 44:
                    System.out.println("\n[!] Info : - Fragment header found\n"); // If the MTU exceed fragment will be used.
                    nextHeader = readNextHeader(buffer, nextHeader);
                    if (nextHeader == -1) return;
                    break;
                case 51:
                    System.out.println("[!] Info : - Authentification Header found\n"); // To check the authenticity of the packet.
                    this.nextHeader = readNextHeader(buffer, nextHeader);
                    if (nextHeader == -1) return;
                    break;
                case 50:
                    System.out.println("[!] Info : - Encapsulating Security Payload Header found\n"); // Header to say that there is encrypted data for secure communication
                    nextHeader = readNextHeader(buffer, nextHeader);
                    if (nextHeader == -1) return;
                    break;
                case 60:
                    System.out.println("[!] Info : - Destination Options Header found\n"); // Options that need to be examined only by thee destination of the packet
                    readNextHeader(buffer, nextHeader);
                    if (nextHeader == -1) return;
                    break;
                case (byte) 135:
                    System.out.println("[!] Info : - Mobility Header found\n"); // Useless for us because we use Ethernet.
                    readNextHeader(buffer, nextHeader);
                    if (nextHeader == -1) return;
                    break;
                case (byte) 139:
                    System.out.println("[!] Info : - Host Identity Header found\n"); // Used for Host Identity Protocol version 2 (HiPv2).
                    readNextHeader(buffer, nextHeader);
                    if (nextHeader == -1) return;
                    break;
                case (byte) 140:
                    System.out.println("[!] Info : - Shim6 Header found\n"); // Used foor Shim6.
                    readNextHeader(buffer, nextHeader);
                    if (nextHeader == -1) return;
                    break;
                case 6:
                    System.out.println("[!] Info : - TCP Header found\n"); // TCP.
                    return;
                case 17:
                    System.out.println("[!] Info : - UDP Header found\n"); // UDP.
                    return;
                case 58:
                    System.out.println("[!] Info : - ICMPv6 Header found\n"); // ICMPv6.
                    return;
                case 59:
                    System.out.println("[!] Info : - No Next Header found\n"); // No Next Header so no upper layers.
                    return;
                default:
                    System.out.println("[X] - Error : Unknow Next Header : " + nextHeader);
                    return;
            }
        }
    }

    /**
     * Function read next header and skip it until I find TCP, UDP or no more header.
     * @param buffer ByteBuffer to get information from the IPv6 Header.
     * @param currentHeaderType current next header.
     * @return byte that represent the next header type.
     */
    private byte readNextHeader(ByteBuffer buffer, byte currentHeaderType) {

        byte nextHeader = buffer.get();  // Get the header
        byte headerLength = buffer.get();  // Get the size of the header withouth the size of the headerLength.

        // Debug.
        //System.out.printf("[*] - Next Header: %d (Hex: 0x%02X)\n", nextHeader & 0xFF, nextHeader & 0xFF);
        //System.out.printf("[*] - Header Length: %d\n", headerLength);
        //System.out.printf("[*] - Current Buffer Position: %d (Limit: %d)\n", buffer.position(), buffer.limit());

        // So many I didn't want to do all...
        int skipLength;
        switch (currentHeaderType & 0xFF) {
            case 0:  // Hop-by-Hop Options header.
            case 60:  // Destination options header.
                skipLength = (headerLength + 1) * 8 - 2;  // To go to the next nextHeader.
                break;
            case 43:  // Routing header.
                skipLength = (headerLength + 1) * 8 - 2;
                break;
            case 44:  // Fragment header.

                skipLength = 8 - 2;
                break;
            case 51: // Authentification header.
                skipLength = (headerLength + 2) * 4 - 2;
                break;

            case 6:  // TCP header. No header next only data.
            case 17: // UDP header
            case 58: // ICMPv6 header
            case 59: // No Next header.
                System.out.println("[!] Info : Reached a transport layer protocol or no more headers to process.\n");
                return nextHeader;

            default:
                System.err.printf("[X] - Error: Unsupported or unrecognized header type");
                return -1;
        }


        // We get to the nextHeader if there is one.
        buffer.position(buffer.position() + skipLength);

        return nextHeader;
    }




    public int getUnsignedNextHeader() {
        return this.nextHeader & 0xFF;
    }

    @Override
    public String toString() {
        return String.format("\nIPv6 Header\n---------------------\n"
        + "[*] - Version: %s\n"
        + "[*] - TrafficClass: %s\n"
        + "[*] - Flow Label: %s\n"
        + "[*] - Payload Length: %s\n"
        + "[*] - Next Header: %s\n"
        + "[*] - Hop Limit: %s\n"
        + "[*] - Source Address: %s\n"
        + "[*] - Destination Address: %s\n",
        version, PriorityTrafficClass, flowLabel, payloadLength, nextHeader, (hopLimit & 0xFF), bytesToIPv6(sourceAddress), bytesToIPv6(destinationAddress));
    }


}
