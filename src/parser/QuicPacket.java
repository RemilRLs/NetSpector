package parser;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Class used to parse and print QUIC packet information.
 */

public class QuicPacket {
    private boolean isLongHeader; // To know if it's a long header or not.
    private String packetTypeString; // Packet type like (client packet or server packet).
    //private String magicString; // UIC I think it used to identify if the packet is from client or server.
    private int version; // Version of QUIC.
    private int packetType;

    /**
     * Constructor to parse a QUIC packet and analyze it.
     * @param data Byte array containing the QUIC packet.
     */
    public QuicPacket(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.BIG_ENDIAN);

        byte firstByte = buffer.get();
        isLongHeader = (firstByte & 0x80) != 0;

        if (isLongHeader) {
            packetType = (firstByte & 0x30) >> 4;
            packetTypeString = getPacketTypeString();

            version = buffer.getInt();


        } else {
            packetTypeString = "Short Header";

        }
    }

    /**
     *  Get the packet type string and return a string representation of it (like if it is a client packet or a server packet).
     * @return String representation of the packet type.
     */
    public String getPacketTypeString() {
        switch (packetType) {
            case 0x11:
                packetTypeString = "Client Packet";
                break;
            case 0x10:
                packetTypeString = "Server Packet";
                break;
            case 0x01:
                packetTypeString = "Public Reset";
                break;
            case 0x00:
                packetTypeString = "Version Negotiation";
                break;
            default:
                packetTypeString = "Unknown";
                break;


        }
        return packetTypeString;
    }

    @Override
    public String toString() {
        return String.format(
                "\nQUIC Packet\n---------------------\n" +
                        "[*] - Header Type: %s\n" +
                        "[*] - Packet Type: %s\n" +
                        "[*] - Version: 0x%08X\n",
                isLongHeader ? "Long Header" : "Short Header",
                packetTypeString,
                version
        );
    }
}
