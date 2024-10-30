package parser;

import static parser.PacketUtils.bytesToMAC;
import static parser.PacketUtils.bytesToIPv4;

import java.nio.ByteBuffer;

/**
 * Class used to parse and print ARP packet information.
 */
public class ARPPacket {
    // https://www.geeksforgeeks.org/arp-protocol-packet-format/

    private short hardwareType; // Field that specify on which network ARP is running (for us it will be Ethernet).
    private short protocolType; // Field of define the protocol most of the time 0x800 for IPv4.
    private byte hardwareLength; // I don't know why we have to take that because it can only be 6 bytes.
    private byte protocolLength; // Same but for IPv4.
    private short opcode; // Know if the packet is the Reply (2) or the one that request (1).
    private byte[] senderHardwareAddress; // MAC Address of this sender. We never know if the hardwareLength ou protocolLength change so I prefer to do a byte[]
    private byte[] senderProtocolAddress; // IPv4 Address of the sender.
    private byte[] targetHardwareAddress; // MAC Address of the target.
    private byte[] targetProtocolAddress; // IPv4 Address of the target.

    /**
     * Constructor of the class to intiialize and parse the ARP packet from a ByteBuffer.
     * @param buffer ByteBuffer containing the ARP.
     */
    public ARPPacket(ByteBuffer buffer) {
        this.hardwareType = buffer.getShort();
        this.protocolType = buffer.getShort();
        this.hardwareLength = buffer.get();
        this.protocolLength = buffer.get();
        this.opcode = buffer.getShort();
        this.senderHardwareAddress = new byte[hardwareLength];
        this.senderProtocolAddress = new byte[protocolLength];
        this.targetHardwareAddress = new byte[hardwareLength];
        this.targetProtocolAddress = new byte[protocolLength];

        buffer.get(senderHardwareAddress); // I fill the tab with the size of the hardwareLength and same for below.
        buffer.get(senderProtocolAddress);
        buffer.get(targetHardwareAddress);
        buffer.get(targetProtocolAddress);
    }


    /**
     * Check if the opcode is a request or a reply.
     * @return String representation of the opcode.
     */

    public String checkOpcode(){
        return this.opcode == 1 ? "Request" : "Reply";
    }

    /**
     * Create a string representation of the ARP packet.
     * @return String representation of the ARP packet.
     */

    @Override
    public String toString() {
        return String.format("ARP Packet\n---------------------\n"
                + "[*] - Hardware Type : %s\n"
                + "[*] - Protocol Type : %s\n"
                + "[*] - Hardware Size : %s\n"
                + "[*] - Protocol Size : %s\n"
                + "[*] - Opcode : %s\n"
                + "[*] - Sender Hardware Address : %s\n"
                + "[*] - Sender Protocol Address : %s\n"
                + "[*] - Target Hardware Address : %s\n"
                + "[*] - Target Protocol Address : %s\n",
                hardwareType, protocolType, hardwareLength, protocolLength, checkOpcode(), bytesToMAC(senderHardwareAddress), bytesToIPv4(senderProtocolAddress), bytesToMAC(targetHardwareAddress), bytesToIPv4(targetProtocolAddress)

                );
    }

}
