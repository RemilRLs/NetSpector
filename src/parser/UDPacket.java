package parser;

import static parser.PacketUtils.convertByteToASCII;

import java.nio.ByteBuffer;

/**
 * Class used to parse and print UDP packet information.
 */
public class UDPacket {
    // https://fr.wikipedia.org/wiki/User_Datagram_Protocol


    private short protocol; // Protocol used (it will be 17).
    private short sizeHeader; // Size of the UDP header.
    private short sourcePort; // Source port.
    private short destPort; // Destination port.
    private short size; // Size of the packet
    private short checkSum; // Checksum to check if there there is no errors.
    private byte[] data; // Data if there is like DNS.
    /**
     * Constructor to parse a UDP packet and analyze it.
     * @param buffer ByteBuffer to get information from the UDP Header and data if the there is.
     */
    public UDPacket(ByteBuffer buffer){
        //protocol = buffer.getShort();
        //sizeHeader = buffer.getShort();
        sourcePort = buffer.getShort();
        destPort = buffer.getShort();
        size = buffer.getShort();
        checkSum = buffer.getShort();

        int remainingDataLength = buffer.remaining();

        if(remainingDataLength > 0){ // Only if there is data like DNS.
            data = new byte[remainingDataLength];
            buffer.get(data);
        } else{
            data = null;
        }
    }


    /**
     * Get port source.
     * @return Unsigned port source.
     */
    public int getSourcePort() {
        return Short.toUnsignedInt(sourcePort);
    }

    /**
     * Get port destination.
     * @return Unsigned port destination.
     */
    public int getDestPort() {
        return Short.toUnsignedInt(destPort);
    }
    public int getCheckSum(){
        return Short.toUnsignedInt(checkSum);
    }
    /**
     * Get the data from the UDP packet.
     * @return data in byte.
     */
    public byte[] getData() {
        return data;
    }

    @Override
    public String toString() {
        return String.format("\nUDP Packet\n---------------------\n" +
                    "[*] - Source Port : %s \n" +
                    "[*] - Destination Port : %s\n" +
                    "[*] - Length : %s\n" +
                    "[*] - Checksum : %s\n" +
                    "[*] - Data : %s\n",
                    getSourcePort(),
                    getDestPort(),
                    size,
                    getCheckSum(),
                    (data != null) ? convertByteToASCII(data) : "No Data");
    }
}
