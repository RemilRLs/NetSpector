package parser;

import static parser.PacketUtils.bytesToMAC;
import static parser.PacketUtils.bytesToIPv4;
import static parser.PacketUtils.bytesToHex;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Class used to parse and print DHCP packet information.
 */

public class DHCPPacketG {
    // https://support.hpe.com/techhub/eginfolib/networking/docs/switches/5120si/cg/5998-8491_l3-ip-svcs_cg/content/436042653.htm
    // https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol
    private int op; // Operation code (1 = request, 2 = reply)
    private int htype; // Hardware type so for me it is Ethernet.
    private int hlen; // Hardware address length so for me it is 6.
    private int hops; // Number of hops
    private long xid; // Transaction ID
    private int secs; // Seconds elapsed since client started trying to get IP.
    private int flags; // Flags
    private byte[] ciaddr = new byte[4]; // Client IP address
    private byte[] yiaddr = new byte[4]; // Your IP address (the address that the server is offering to the client)
    private byte[] siaddr = new byte[4]; // Server IP address
    private byte[] giaddr = new byte[4]; // Gateway IP address
    private byte[] chaddr = new byte[16]; // WHAAAAAAAAAAAAAAAAAAT why so long
    private String sname; // Server name
    private String file;
    private Map<Integer, byte[]> options = new HashMap<>(); // DHCP options

    /**
     * Constructor to initialize and parse the DHCP packet.
     * @param buffer ByteBuffer containing the DHCP packet.
     * @throws Exception
     */
    public DHCPPacketG(ByteBuffer buffer) throws Exception {
        buffer.order(ByteOrder.BIG_ENDIAN);

        buffer.rewind();

        op = Byte.toUnsignedInt(buffer.get());
        htype = Byte.toUnsignedInt(buffer.get());
        hlen = Byte.toUnsignedInt(buffer.get());
        hops = Byte.toUnsignedInt(buffer.get());
        xid = Integer.toUnsignedLong(buffer.getInt());
        secs = Short.toUnsignedInt(buffer.getShort());
        flags = Short.toUnsignedInt(buffer.getShort());
        buffer.get(ciaddr);
        buffer.get(yiaddr);
        buffer.get(siaddr);
        buffer.get(giaddr);
        buffer.get(chaddr);
        byte[] snameBytes = new byte[64];
        buffer.get(snameBytes);
        sname = new String(snameBytes, StandardCharsets.US_ASCII).trim();
        byte[] fileBytes = new byte[128];
        buffer.get(fileBytes);
        file = new String(fileBytes, StandardCharsets.US_ASCII).trim();


        int magicCookie = buffer.getInt();
        if (magicCookie != 0x63825363) {
            throw new IllegalArgumentException("Invalid DHCP magic cookie");
        }

        while (buffer.hasRemaining()) {
            int optionType = Byte.toUnsignedInt(buffer.get());
            if (optionType == 255) {
                break;
            } else if (optionType == 0) {
                continue;
            } else {
                int optionLength = Byte.toUnsignedInt(buffer.get());
                byte[] optionData = new byte[optionLength];
                buffer.get(optionData);
                options.put(optionType, optionData);
            }
        }
    }




    /**
     * Create a string representation of the DHCP packet.
     * @return String representation of the DHCP packet.
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nDHCP Packet\n---------------------\n");
        sb.append(String.format("[*] - Opcode: %d\n", op));
        sb.append(String.format("[*] - Hardware Type: %d\n", htype));
        sb.append(String.format("[*] - Hardware Address Length: %d\n", hlen));
        sb.append(String.format("[*] - Hops: %d\n", hops));
        sb.append(String.format("[*] - Transaction ID: %d\n", xid));
        sb.append(String.format("[*] - Seconds: %d\n", secs));
        sb.append(String.format("[*] - Flags: %d\n", flags));
        sb.append(String.format("[*] - Client IP Address: %s\n", bytesToIPv4(ciaddr)));
        sb.append(String.format("[*] - Your IP Address: %s\n", bytesToIPv4(yiaddr)));
        sb.append(String.format("[*] - Server IP Address: %s\n", bytesToIPv4(siaddr)));
        sb.append(String.format("[*] - Gateway IP Address: %s\n", bytesToIPv4(giaddr)));
        sb.append(String.format("[*] - Client Hardware Address: %s\n", bytesToMAC( Arrays.copyOf(chaddr, hlen)))); // I don't know why the chaddr is 16 bytes long but I only need only the size of hlen.
        sb.append(String.format("[*] - Server Name: %s\n", sname));
        sb.append(String.format("[*] - Boot File Name: %s\n", file));
        sb.append("[*] - Options:\n");

        for (Map.Entry<Integer, byte[]> entry : options.entrySet()) {
            sb.append(String.format("   Option %d: %s\n", entry.getKey(), bytesToHex(entry.getValue())));
        }

        return sb.toString();
    }
}
