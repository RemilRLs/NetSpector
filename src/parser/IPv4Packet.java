package parser;

import static parser.PacketUtils.bytesToIPv4;

// https://networklessons.com/cisco/ccna-routing-switching-icnd1-100-105/ipv4-packet-header

import java.nio.ByteBuffer;

public class IPv4Packet {
    private byte versionPlusHeaderLength; // I couldn't take 4 bit by 4 bit so I take one byte.
    private byte typeOfService; // Quality of Service.
    private short totalLength; // Size of the packet Header.
    private short identification; // Number of identification if there is fragmented packet.
    private short ipFlagFragmentOffset; // IP Flags
    private byte timeToLive; // Jump to router to router (decrement).
    private byte protocol; // Allows me to know which protocol is encapsulated in the IPv4 packet data (useful).
    private short headerCheckSum; // Allow us to check if the header is good or not.
    private byte[] sourceAddress = new byte[4]; // IPv4 source.
    private byte[] destinationAddress = new byte[4]; // IPv4 destination.
    private int version; // Version.
    private int headerLength; // IPv4 Header size to use to send it to the next layer upper.
    private byte [] options;
    private int paddingLength;

    /**
     * Constructor allowing to retrieve and initialize IPv4 Header values
     * @param buffer ByteBuffer to get information from the IPv4 Header.
     */

    public IPv4Packet(ByteBuffer buffer) {
            this.versionPlusHeaderLength = buffer.get();
            this.version = (versionPlusHeaderLength >> 4) & 0x0F; // Shifts the first 4 bits to the right which allows me to overwrite the other 4 remaining leaving only the version.
            this.headerLength = (versionPlusHeaderLength & 0x0F) * 4; // Get the last 4 bits to get the Packet Header size (was hard to find). Extract 4 bits of the right and use the mask 0x0F for 00001111.
            this.typeOfService = buffer.get();
            this.totalLength = buffer.getShort();
            this.identification = buffer.getShort();
            this.ipFlagFragmentOffset = buffer.getShort();
            this.timeToLive = buffer.get();
            this.protocol = buffer.get();
            this.headerCheckSum = buffer.getShort();
            buffer.get(sourceAddress);
            buffer.get(destinationAddress);

            int optionsLength = this.headerLength - 20;
            if (optionsLength > 0) {
                this.options = new byte[optionsLength];
                buffer.get(this.options);
            }

    }


    private int getUnsignedTTL(){
        return this.timeToLive & 0xFF;
    }

    private int getUnsignedCheckSum(){
        return this.headerCheckSum & 0xFF;
    }

    private int getUnsignedIdentification(){
        return this.identification & 0xFF;
    }

    public int getUnsignedProtocolIdentifier(){return this.protocol & 0xFF;}

    public String getSourceAddress(){
        return bytesToIPv4(sourceAddress);
    }

    public String getDestinationAddress(){
        return bytesToIPv4(destinationAddress);
    }



    @Override
    public String toString() {
        return String.format("IPv4 Header\n---------------------\n[*] - Version %d\n[*] - Header Length : %d\n[*] - Type of Service : %d\n[*] - Total Length Header : %d\n[*] - Identification : %d\n[*] - Flag and Fragment Offset : %d\n[*] - Time to live : %d\n[*] - Protocol : %d\n[*] - Header Checksum : %d\n[*] - Source Address : %s\n[*] - Destination Address : %s",
        version, headerLength, typeOfService, totalLength, getUnsignedIdentification(), ipFlagFragmentOffset, getUnsignedTTL(), protocol, getUnsignedCheckSum(), bytesToIPv4(sourceAddress), bytesToIPv4(destinationAddress));
    }
}
