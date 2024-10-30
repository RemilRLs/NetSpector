package parser;

import java.nio.ByteBuffer;

/**
 * Class used to parse and print ICMPv6 packet information.
 */
public class ICMPv6Packet {
    // https://fr.wikipedia.org/wiki/Internet_Control_Message_Protocol_V6

    private byte type; // Most of the time (Echo Request : 128) & (Echo Reply : 129).
    private byte code; // Code.
    private int checkSum; // Check if there is error.
    private byte[] messageBody; // Additional data.

    public ICMPv6Packet(ByteBuffer buffer) {
        this.type = buffer.get();
        this.code = buffer.get();
        this.checkSum = buffer.getInt();

        int remainingDataLength = buffer.remaining();
        this.messageBody = new byte[remainingDataLength];
        buffer.get(messageBody);
    }

    /**
     *  Transform data of ICMPv4 Packet to string.
     * @return String representation of the data.
     */
    private String getDataString(){
        StringBuilder result = new StringBuilder();
        for (byte b : messageBody) {
            result.append(String.format("%02X ", b));
        }

        return result.toString();
    }

    @Override
    public String toString() {
        return String.format("\nICMPv6 Header\n---------------------\n"
                + "[*] - Type %s\n"
                + "[*] - Code %s\n"
                + "[*] - CheckSum %s\n"
                + "[*] - Message Body %s\n",
                (type & 0xFF), code, checkSum, getDataString());

    }

}
