package parser;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.nio.charset.StandardCharsets;

public class TCPStream {
    private String ip1; // IP address of the first host.
    private String ip2; // IP address of the second host.
    private int port1; // Port of the first host.
    private int port2; // Port of the second host.


    private List<TCPDataSegment> dataSegments1to2; // Client to server
    private List<TCPDataSegment> dataSegments2to1; // Server to client

    public TCPStream(String ip1, String ip2, int port1, int port2) {
        this.ip1 = ip1;
        this.ip2 = ip2;
        this.port1 = port1;
        this.port2 = port2;
        this.dataSegments1to2 = new ArrayList<>();
        this.dataSegments2to1 = new ArrayList<>();
    }
    /**
     * Add data segment to follow it.
     * @param sequenceNumber  Sequence number
     * @param data Data from the next TCP Packet.
     */
    public void addDataSegment(String segmentSourceIP, int segmentSourcePort, long sequenceNumber, byte[] data) {
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

        //
        if (segmentSourceIP.equals(ip1) && segmentSourcePort == port1) { // Client

            if (!containsSequenceNumber(dataSegments1to2, sequenceNumber)) { // I don't want to add the same sequenceNumber twice.
                TCPDataSegment segment = new TCPDataSegment(sequenceNumber, data); // I create a new segment with the sequenceNumber and the data.
                dataSegments1to2.add(segment);
                dataSegments1to2.sort(Comparator.comparingLong(TCPDataSegment::getSequenceNumber)); // I sort the list of segment.
            }
        } else if (segmentSourceIP.equals(ip2) && segmentSourcePort == port2) { // Server (most of the time)
            if (!containsSequenceNumber(dataSegments2to1, sequenceNumber)) {
                TCPDataSegment segment = new TCPDataSegment(sequenceNumber, data);
                dataSegments2to1.add(segment);
                dataSegments2to1.sort(Comparator.comparingLong(TCPDataSegment::getSequenceNumber));
            }
        }
    }

    /**
     * Check if the sequence number is already in the list of segments.
     * @param segments List of segments.
     * @param sequenceNumber Sequence number to check.
     * @return
     */
    private boolean containsSequenceNumber(List<TCPDataSegment> segments, long sequenceNumber) {
        /**
         * So I go through all segments and check if the sequenceNumber is already in the list.
         */
        return segments.stream().anyMatch(segment -> segment.getSequenceNumber() == sequenceNumber);
    }

    public String getDataFromIp1ToIp2() {
        return reassembleData(dataSegments1to2);
    }

    public String getDataFromIp2ToIp1() {
        return reassembleData(dataSegments2to1);
    }

    private String reassembleData(List<TCPDataSegment> segments) {

        /**
         * Inside a session most of the time there is multiple dataSegments.
         * Every dataSegments is link to the sessionID
         * Stream allow me allow me to do a flux of segments
         * I want to transform each segment into is size (int)
         * and sum it !
         * So mapToInt is going to go through all segment and do a sum.
         */

        int totalLength = segments.stream().mapToInt(s -> s.getData().length).sum();
        byte[] reassembledData = new byte[totalLength];

        int currentPos = 0;

        /**
         * I go through aller segment and copy them into fullData.
         */

        for (TCPDataSegment segment : segments) {
            System.arraycopy(segment.getData(), 0, reassembledData, currentPos, segment.getData().length);
            currentPos += segment.getData().length;
        }
        return new String(reassembledData, StandardCharsets.UTF_8);
    }
    /**
     * Transform the data into a string.
     * @return Data in string.
     */
    public String getFullData() {
        StringBuilder result = new StringBuilder();
        result.append("Data from ").append(ip1).append(":").append(port1).append(" to ").append(ip2).append(":").append(port2).append("\n");
        result.append(getDataFromIp1ToIp2()).append("\n");
        result.append("Data from ").append(ip2).append(":").append(port2).append(" to ").append(ip1).append(":").append(port1).append("\n");
        result.append(getDataFromIp2ToIp1()).append("\n");
        return result.toString();
    }

    /**
     * Check if the data isHTTP or not.
     * @return True if the data is HTTP, false otherwise.
     */
    public boolean isHTTP() {
        String data1to2 = getDataFromIp1ToIp2().trim();
        String data2to1 = getDataFromIp2ToIp1().trim();

        return data1to2.contains("GET") || data1to2.contains("POST") || data1to2.contains("HTTP/1.1") ||
                data2to1.contains("GET") || data2to1.contains("POST") || data2to1.contains("HTTP/1.1") ||
                data2to1.contains("HTTP/1.0") || data2to1.contains("Host:");
    }

    @Override
    public String toString() {
        return getFullData();
    }
}

class TCPDataSegment {
    private long sequenceNumber;
    private byte[] data;

    public TCPDataSegment(long sequenceNumber, byte[] data) {
        this.sequenceNumber = sequenceNumber;
        this.data = data;
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    public byte[] getData() {
        return data;
    }
}
