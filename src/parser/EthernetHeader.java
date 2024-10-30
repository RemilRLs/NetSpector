package parser;

import static parser.PacketUtils.bytesToMAC;

import java.nio.ByteBuffer;

/**
 * Class used to parse and print Ethernet Header information.
 */
public class EthernetHeader {
    private byte[] destinationMACAddress = new byte[6]; // Destination MAC Address.
    private byte[] sourceMACAddress = new byte[6]; // Source MAC Address.
    private short etherType; // Ether type which will specify the protocol used on the layer above.


    /**
     * Constructor which will intialize the EthernetHeader in order to have information on the data of the packet itself such as the layer above (protocol used)
     * @param buffer ByteBuffer to get information from the Ethernet Header.
     */

    public EthernetHeader(ByteBuffer buffer) {
        buffer.get(destinationMACAddress);
        buffer.get(sourceMACAddress);
        this.etherType = buffer.getShort();
    }

    /**
     * Get the EtherType to know the protocol layer above.
     * @return EtherType (of course)
     */
    public short getEtherType() {
        return etherType;
    }


    @Override
    public String toString() {
        return String.format("\nEthernet Header\n" +
                        "---------------------\n" +
                        "[*] - Ethertype : 0x%04X\n" +
                        "[*] - Destination MAC: %s\n" +
                        "[*] - Source MAC : %s\n",
                etherType, bytesToMAC(destinationMACAddress), bytesToMAC(sourceMACAddress));
    }
}
