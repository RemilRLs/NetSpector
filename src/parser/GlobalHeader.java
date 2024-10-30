package parser;

import java.nio.ByteBuffer;

public class GlobalHeader {
    private final int magicNumber; // Magic number to determine if it's a .pcap file.
    private final short versionMajor; // Major Version.
    private final short versionMinor; // Minor Version
    private final int thisZone; // GMT to local correction
    private final int sigfigs; // Accuracy of timestamps.
    private final int snaplen; // Max length of captured packets, in octets.
    private final int network; // Link layer header type (for us Ethernet).

    /**
     * Constructor which will initialize the Global Header allowing information on the .pcap file which has been validated.
     * @param buffer ByteBuffer that we have previously put in memory allowing us to obtain the Header of the .pcap
     */

    public GlobalHeader(ByteBuffer buffer) {
        this.magicNumber = buffer.getInt();
        this.versionMajor = buffer.getShort();
        this.versionMinor = buffer.getShort();
        this.thisZone = buffer.getInt();
        this.sigfigs = buffer.getInt();
        this.snaplen = buffer.getInt();
        this.network = buffer.getInt();
    }

    public int getMagicNumber() {
        return magicNumber;
    }
    public short getVersionMajor() {
        return versionMajor;
    }
    public short getVersionMinor() {
        return versionMinor;
    }
    public int getThisZone() {
        return thisZone;
    }
    public int getSigfigs() {
        return sigfigs;
    }
    public int getSnaplen() {
        return snaplen;
    }
    public int getNetwork() {
        return network;
    }

    @Override
    public String toString() {
        return String.format(
                "\nGlobal Header\n---------------------\n" +
                        "[*] - Magic Number: 0x%08X\n" +
                        "[*] - Version: 0x%02X.0x%02X\n" +
                        "[*] - This Zone: %d\n" +
                        "[*] - Sigfigs: %d\n[*] - Snaplen: %d\n" +
                        "[*] - Network: 0x%08X",
                magicNumber, versionMajor, versionMinor, thisZone, sigfigs, snaplen, network
        );
    }
}
