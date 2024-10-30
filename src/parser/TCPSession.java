package parser;

import static parser.PacketUtils.convertByteToASCII;


import java.util.ArrayList;
import java.util.List;
import java.nio.charset.StandardCharsets;


/**
 * Class used to follow the session of a TCP file in order to subsequently be able to identify the protocol.
 */
public class TCPSession {
    private String sourceIP;
    private String destinationIP;
    private int sourcePort;
    private int destPort;
    private long sequenceNumber;
    private long ackNumber;
    private List<byte[]> dataSegments;

    /**
     * Class and constructor allowing me to follow the session of a TCP file in order to subsequently be able to identify the protocol
     * @param sourceIP  Source IP from IPv4 or IPv6.
     * @param destinationIP  Destination IP from IPv4 or IPv6.
     * @param sourcePort  Source port.
     * @param destPort Destination port.
     */
    public TCPSession(String sourceIP, String destinationIP, int sourcePort, int destPort, long sequenceNumber, long ackNumber) {
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.sourcePort = sourcePort;
        this.destPort = destPort;
        this.sequenceNumber = 0;
        this.ackNumber = 0;
        this.dataSegments = new ArrayList<>();
    }

    /**
     * Add data segment to follow it.
     * @param sequenceNumber  Sequence number
     * @param data Data from the next TCP Packet.
     */
    public void addDataSegment(long sequenceNumber, byte[] data){
        if (data == null || data.length == 0) {
            return;
        }

        boolean isPadding = true;
        for (byte b : data) {
            if (b != 0x00) {
                isPadding = false;
                break;
            }
        }

        if (isPadding) { // I don't want to add padding in the sequenceNumber ! My god that bug...
            return;
        }

        if(sequenceNumber >= this.sequenceNumber){
            //System.out.println("Data Captured: " + new String(data, StandardCharsets.UTF_8));
            //printHex(data);
            this.dataSegments.add(data);
            this.sequenceNumber = sequenceNumber + data.length;
        }
    }

    /**
     * Get the full data of the TCP session.
     * @return Full data of the TCP session.
     */
    public byte[] getFullDataTCPSession(){

        /**
         * Inside a session most of the time there is multiple dataSegments.
         * Every dataSegments is link to the sessionID
         * Stream allow me allow me to do a flux of segments
         * I want to transform each segment into is size (int)
         * and sum it !
         * So mapToInt is going to go through all segment and do a sum.
         */
        int totalLength = dataSegments.stream().mapToInt(segment -> segment.length).sum();
        byte[] fullData = new byte[totalLength];

        int currentPos = 0;
        /**
         * I go through aller segment and copy them into fullData.
         */
        for (byte[] segment : dataSegments) {
            System.arraycopy(segment, 0, fullData, currentPos, segment.length);
            currentPos += segment.length;
        }

        return fullData;

    }

    public String getFullDataAsASCII() {
        byte[] fullData = getFullDataTCPSession();
        return convertByteToASCII(fullData);
    }

    /**
     * Transform the data into a string.
     * @return Data in string.
     */

    public String getFullDataAsString() {
        byte[] fullData = getFullDataTCPSession();
        return new String(fullData, StandardCharsets.UTF_8); // Convert all the data into UTF_8.
    }

    /**
     * Check if the data isHTTP or not.
     * @return True if the data is HTTP, false otherwise.
     */

    public boolean isHTTP() {
        String fullData = getFullDataAsString().trim();

        return fullData.contains("GET") || fullData.contains("POST") || fullData.contains("HTTP/1.1") || fullData.contains("HTTP/1.0") || fullData.contains("Host:");
    }



    @Override
    public String toString() {
        return String.format("\nTCP Session [%s:%s] ->  [%s:%s]\n" +
                "[*] - Sequence : %s\n" +
                "[*] - Data Segment Size : %s\n" +
                "[*] - Data : %s\n",
                sourceIP, destinationIP, sourcePort, destPort, sequenceNumber, dataSegments.size(), getFullDataAsASCII());
    }
}
