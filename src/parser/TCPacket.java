package parser;

import static parser.PacketUtils.convertByteToASCII;

import java.nio.ByteBuffer;

/**
 * Class used to parse and print TCP packet information.
 */
public class TCPacket {
    private short sourcePort; // Source port.
    private short destPort; // Destination port.
    private int sequenceNumber; // Sequence number.
    private int ackNumber; // Acnowledge number.
    private short sizeHeaderFlag;
    private byte sizeHeader;
    private short flags;
    private short windows; // Don't care.
    private short checkSum; // Checksum to check if there is no errors.
    private short urgPointer;
    private byte[] options;
    private byte[] data; // Data if there is (like HTTP, FTP for my case).

    /**
     * Constructor to parse a TCP packet and analyze it.
     * @param buffer ByteBuffer to get information from the TCP Header and data if the there is.
     */
    TCPacket(ByteBuffer buffer){
        //buffer.rewind(); // Thanks god you exist !

        sourcePort = buffer.getShort();
        destPort = buffer.getShort();
        sequenceNumber = buffer.getInt();
        ackNumber = buffer.getInt();
        sizeHeaderFlag = buffer.getShort();
        sizeHeader = (byte) ((sizeHeaderFlag >> 12) & 0x0F); // I want only the four first byte.
        flags = (short) (sizeHeaderFlag & 0x01FF); ; // 0000 0001 1111 1111 | Because there is 9 bits of flag that are interesting.
        windows = buffer.getShort();
        checkSum = buffer.getShort();
        urgPointer = buffer.getShort();

        int headerSize = sizeHeader * 4; // DWORD.
        int optionsLength = headerSize - 20; // Default 20.

        if (optionsLength > 0) {
            options = new byte[optionsLength];
            buffer.get(options);
        }

        int remainingDataLength = buffer.remaining();
        if (remainingDataLength > 0) {
            data = new byte[remainingDataLength];
            buffer.get(data);
        } else {
            data = null;
        }

    }

    /**
     * Get the data buffer.
     * @return Data buffer.
     */
    public ByteBuffer getDataBuffer(){
        return ByteBuffer.wrap(data);
    }

    /**
     * Get sequence number to follow TCP.
     * @return Sequence number.
     */

    public long getSequenceNumber(){
        return Integer.toUnsignedLong((sequenceNumber));
    }

    /**
     * Get Acknowledge
     * @return Acknowledge number.
     */

    public long getAckNumber(){
        return Integer.toUnsignedLong((ackNumber));
    }

    /**
     * Get source port (can't use)
     * @return Source port.
     */

    public int getSourcePort() {
        return sourcePort & 0xFFFF;
    }


    public int getDestPort() {
        return destPort & 0xFFFF;
    }


    /**
     * Get data from the TCP Packet.
     * @return Data Segment of TCP.
     */
    public byte[] getData(){
        return data;
    }

    /**
     * Flag indicator to transform in string
     * @return Flag in string.
     */

    public String getFlaginString(){
        StringBuilder result = new StringBuilder();

        if ((flags & 0x20) != 0) result.append("URG ");
        if ((flags & 0x10) != 0) result.append("ACK ");
        if ((flags & 0x08) != 0) result.append("PSH ");
        if ((flags & 0x04) != 0) result.append("RST ");
        if ((flags & 0x02) != 0) result.append("SYN ");
        if ((flags & 0x01) != 0) result.append("FIN ");

        return result.toString();
    }

    @Override
    public String toString(){
        return String.format("\nTCP Packet\n---------------------\n" +
                "[*] - Source Port : %s\n" +
                "[*] - Destination Port : %s\n" +
                "[*] - Sequence Number  : %s\n" +
                "[*] - Acknowledge Number : %s\n" +
                "[*] - Flag : %s\n" +
                "[*] - Data : %s\n",
                getSourcePort(), getDestPort(), getSequenceNumber() , getAckNumber(),  getFlaginString(), convertByteToASCII(data));
    }

}
