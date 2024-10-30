package parser;

import java.nio.ByteBuffer;


public class PacketHeader {
    private final int ts_sec; // Timestamp seconds.
    private final int ts_usec; // Timestamp microseconds.
    private final int incl_len; // Size of the packet in bytes. Going to use that one to go the the next packet Header.
    private final int orig_len; // Actual length of packet.


    /**
     * Constructor which will initialize the Packet Header allowing information of each packet.
     * @param buffer ByteBuffer to get information from the Packet Header.
     */
    public PacketHeader(ByteBuffer buffer) {
        this.ts_sec = buffer.getInt();
        this.ts_usec = buffer.getInt();
        this.incl_len = buffer.getInt();
        this.orig_len = buffer.getInt();
    }

    public int getTsSec() {
        return ts_sec;
    }
    public int getTsUsec() {
        return ts_usec;
    }
    public int getIncLen() {
        return incl_len;
    }
    public int getOrinLen() {
        return orig_len;
    }

    @Override
    public String toString() {
        return String.format(
                "\nPacket Header\n---------------------\n[*] - Timestamp (EPOCH) : %d seconds\n[*] - Microseconds : %d ms\n[*] - Captured Packet Length : %d bytes\n[*] - Original Packet Length : %d bytes\n",
                ts_sec, ts_usec, incl_len, orig_len);
    }

}
