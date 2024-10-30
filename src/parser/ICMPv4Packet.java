package parser;
import java.nio.ByteBuffer;

public class ICMPv4Packet {

    // https://networkdirection.net/articles/network-theory/icmpforipv4/
    // https://fr.wikipedia.org/wiki/Internet_Control_Message_Protocol
    // https://support.huawei.com/enterprise/en/doc/EDOC1100174721/9dff3e87/icmp-echo-request-reply-message

    private byte type; // Most of the time echo (0) and (8) for echo request.
    private byte code; // 0 most of the time
    private short checkSum; // To check the packet ICMPv4.
    private short identifier; // Identifiant for matching Echo Replies/Request to the Echo Request/Replies.
    private short sequenceNumber; // Sequence number for matching Echo Replies/Request to the Echo Request/Replies.
    private byte[] data; // Data received in the echo message that have been returned in the echo reply message.

    private IPv4Packet originalIPv4Packet = null; // Just in case if I have type 3 (Destination Unreachable".

    /**
     * Constructor of the class to intiialize and parse the ICMPv4 packet from a ByteBuffer.
     * @param buffer ByteBuffer containing the ICMPv4.
     */
    public ICMPv4Packet(ByteBuffer buffer) {
        this.type = buffer.get();
        this.code = buffer.get();
        this.checkSum = buffer.getShort();

        switch(type) {
            case 0: // Echo Reply.
            case 8: //  Echo Request.
                this.identifier = buffer.getShort();
                this.sequenceNumber = buffer.getShort();
                break;
            case 3: // Destination Unreachable.
                buffer.getInt(); // I don't mind about the but 32 bits.
                byte[] originalIPHeaderTabByte = new byte[20]; // They say 20 bytes for the IPv4 Packet Header.
                buffer.get(originalIPHeaderTabByte);

                ByteBuffer ipv4Buffer = ByteBuffer.wrap(originalIPHeaderTabByte); // I create a buffer to transmet to my class IPv4.
                this.originalIPv4Packet = new IPv4Packet(ipv4Buffer);
                break;
            default:
                break;


        }


        int remainingDataLength = buffer.remaining();
        this.data = new byte[remainingDataLength]; // I get the data.
        buffer.get(this.data);
    }

    /**
     * Get the type of the ICMPv4 packet.
     * @return String representation of the type.
     */
    public String getMessageType() {
        switch (type) {
            case 0:
                return "Echo Reply";
            case 3:
                return "Destination Unreachable";
            case 4:
                return "Source Quench (Congestion Control)";
            case 5:
                return "Redirect Message";
            case 8:
                return "Echo Request";
            case 9:
                return "Router Advertisement";
            case 10:
                return "Router Solication";
            case 11:
                return "Time Exceeded";
            case 12:
                return "Parameter Problem: Bad IP header";
            case 13:
                return "Timestamp Request";
            case 14:
                return "Timestamp Reply";
            case 17:
                return "Address Mask Request";
            case 18:
                return "Address Mask Reply";
            default:
                return "Unknown ICMPv4 Type";
        }
    }

    /**
     *  Transform data of ICMPv4 Packet to string.
     * @return String representation of the data.
     */
    private String getDataAsString() {
        StringBuilder result = new StringBuilder();
        for (byte b : data) {
            result.append(String.format("%02X ", b));
        }
        return result.toString();
    }

    @Override
    public String toString() {
        StringBuilder result = new StringBuilder();
        result.append(String.format("\nICMPv4 Header\n---------------------\n"
                        + "[*] - Type: %d (%s)\n"
                        + "[*] - Code: %d\n"
                        + "[*] - Checksum: 0x%04X\n"
                        + "[*] - Identifier: %d\n"
                        + "[*] - Sequence Number: %d\n"
                        + "[*] - Data: %s\n",
                type, getMessageType(), code, checkSum & 0xFFFF, identifier & 0xFFFF, sequenceNumber & 0xFFFF, getDataAsString()));

        if(type == 3 && (code >= 0 && code <= 15)){
            result.append(String.format("\n \u21B4\n[*] - Original IPv4 Packet Data\n" + originalIPv4Packet.toString()));
        }

        return result.toString();
    }



}
