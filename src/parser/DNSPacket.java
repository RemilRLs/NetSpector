package parser;

import static parser.PacketUtils.bytesToMAC;
import static parser.PacketUtils.bytesToIPv4;
import static parser.PacketUtils.bytesToIPv6;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.ArrayList;
import java.nio.charset.StandardCharsets;

/**
 * DNS Packet class used to parse and print DNS packet information.
 */
public class DNSPacket {

    private List<DNSAnswer> dnsAnswers;
    // https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf

    private int transactionId; // Because if I take short I had some bug because a short can only take between -32768 and 32767 in Java and the transactionId can be at more than 65535.
    private boolean isResponse; // 1 bit to know if it is a response or not.
    private int opcode; // 4 bits to know the type of query.
    private boolean isAuthoritativeAnswer; // 1 bit to know if the server is authoritative.
    private boolean isTruncated; // 1 bit to know if the message was truncated.
    private boolean isRecursionDesired; // 1 bit to know if the client wants a recursive query.
    private boolean isRecursionAvailable; // 1 bit to know if the server can do a recursive query.
    private int responseCode; // 4 bits to know the response code.
    private int questionCount; // 16 bits to know the number of questions.
    private int answerCount; // 16 bits to know the number of answers.
    private int authorityCount; //
    private int additionalCount; //
    private String domainName; // Domain name.
    private int queryType; // Type of query.
    private int queryClass; // Class of query.

    private int flags;

    /**
     * Constructor to parse a DNS packet and analyze it.
     * @param buffer ByteBuffer to get information from the DNS Header and data if the there is some.
     */
    public DNSPacket(ByteBuffer buffer){

        buffer.rewind(); // Oh myyyyyyyyyyyyy godddddddddd I don't know why but the position of the buffer had an offset of 4 bytes.
        dnsAnswers = new ArrayList<>();


        transactionId = Short.toUnsignedInt(buffer.getShort());
        flags = Short.toUnsignedInt(buffer.getShort());


        isResponse = (flags & 0x8000) != 0; // 1000 0000 0000 0000 because I want the first bit. I check if the result is different from 0 to have a boolean.
        opcode = (flags >> 11) & 0x0F; // I want the 4 bits of the opcode so I have to shifts 11 bits to the right to erase AA, TC ,RD, RA... and then take the first four bits.
        isAuthoritativeAnswer = (flags & 0x0400) != 0; // 0000 0100 0000 0000
        isTruncated = (flags & 0x0200) != 0; // 0000 0010 0000 0000
        isRecursionDesired = (flags & 0x0100) != 0;
        isRecursionAvailable = (flags & 0x0080) != 0;
        responseCode = flags & 0x000F;


        questionCount = Short.toUnsignedInt(buffer.getShort());
        answerCount = Short.toUnsignedInt(buffer.getShort());
        authorityCount = Short.toUnsignedInt(buffer.getShort());
        additionalCount = Short.toUnsignedInt(buffer.getShort());

        domainName = getDomainName(buffer);
        queryType = buffer.getShort();
        queryClass = buffer.getShort();

        if(answerCount > 0){
            parseAnswerSection(buffer);
        }


    }

    /**
     * Get the domain name from the DNS packet.
     * @param buffer ByteBuffer containing the DNS packet.
     * @return String representation of the domain name.
     */
    private String getDomainName(ByteBuffer buffer) {
        StringBuilder domainName = new StringBuilder();
        int originalPosition = buffer.position();
        boolean isPointer = false;

        try {
            while (true) {
                int length = Byte.toUnsignedInt(buffer.get());

                // I need to check if it's a pointer or not. If that the case first 1100 0000
                if ((length & 0xC0) == 0xC0) {
                    int pointer = ((length & 0x3F) << 8) | Byte.toUnsignedInt(buffer.get());
                    int currentPos = buffer.position();

                    buffer.position(pointer); // I go take the domain.
                    domainName.append(getDomainName(buffer));

                    buffer.position(currentPos);
                    isPointer = true;
                    break;
                }

                // We read everything from the domaine name.
                if (length == 0) {
                    break;
                }

                if (domainName.length() > 0) {
                    domainName.append(".");
                }

                byte[] label = new byte[length];
                buffer.get(label);
                domainName.append(new String(label, StandardCharsets.UTF_8));
            }
        } catch (Exception e) {
            System.err.println("[X] - Error: Failed to read domain name.");
        }

        // We go back to the normal position after reading the domain name.
        if (isPointer) {
            buffer.position(originalPosition + 2);
        }

        return domainName.toString();
    }

    /**
     * Parse the answer section of the DNS packet.
     * @param buffer ByteBuffer containing the DNS packet.
     */

    private void parseAnswerSection(ByteBuffer buffer) {
        for (int i = 0; i < answerCount; i++) {

            String domainNameRequested = getDomainName(buffer);

            int queryType = Short.toUnsignedInt(buffer.getShort());
            int queryClass = Short.toUnsignedInt(buffer.getShort());
            long ttl = Integer.toUnsignedLong(buffer.getInt());
            int dataLength = Short.toUnsignedInt(buffer.getShort());

            if (buffer.remaining() < dataLength) {
                System.err.println("[X] - Error: Not enough data in buffer.");
                break;
            }

            byte[] data = new byte[dataLength];
            buffer.get(data);


            if (queryType == 1 && dataLength == 4) { // Type A for IPv4
                String ipv4 = bytesToIPv4(data);
                dnsAnswers.add(new DNSAnswer(domainNameRequested, getQueryType(queryType), getQueryClass(queryClass), ttl, ipv4));
            } else if (queryType == 28 && dataLength == 16) {
                String ipv6 = bytesToIPv6(data);
                dnsAnswers.add(new DNSAnswer(domainNameRequested, getQueryType(queryType), getQueryClass(queryClass), ttl, ipv6));
            } else { // I think I can add more there... maybe if a I have time TODO !
                dnsAnswers.add(new DNSAnswer(domainNameRequested, getQueryType(queryType), getQueryClass(queryClass), ttl, "Unknown data"));
            }
        }
    }


    public int getTransactionId(){
        return transactionId;
    }

    public boolean isResponse(){
        return isResponse;
    }

    /**
     * Retrieve the type of the DNS query (if the user want IPv4, IPv6, CNAME, etc).
     * @param queryType Type of query.
     * @return String representation of the query type.
     */
    private String getQueryType(int queryType){
        // https://en.wikipedia.org/wiki/List_of_DNS_record_types
        switch(queryType){
            case 1:
                return "A"; // IPv4.
            case 5:
                return "CNAME"; // Canonical name record.
            case 6:
                return "SOA"; // Start authority record.
            case 12:
                return "PTR"; // I don't know what it is but was on the list.
            case 15:
                return "MX"; // Mail.
            case 28:
                return "AAAA"; // IPv6.
            case 33:
                return "SRV"; // Service lovactor.
            default:
                return "Unknown";
        }
    }

    /**
     * Retrieve the class of the DNS query (Internet, Chaos, Hesiod).
     * @param classType Class of query.
     * @return String representation of the query class.
     */

    private String getQueryClass(int classType){
        // https://serverfault.com/questions/220775/what-does-the-in-mean-in-a-zone-file
        switch(queryClass){
            case 1:
                return "IN"; // Internet.
            case 3:
                return "CH"; // Chaos.
            case 4:
                return "HS"; // Hesiod.
            default:
                return "Unknown";
        }
    }

    @Override
    public String toString(){
        StringBuilder result = new StringBuilder();
        result.append(String.format("\nDNS Packet\n---------------------\n" +
                "[*] - Transaction ID : %s\n" +
                "[*] - Is Response : %s\n" +
                "[*] - Opcode : %s\n" +
                "[*] - Is Authoritative Answer : %s\n" +
                "[*] - Is Truncated : %s\n" +
                "[*] - Is Recursion Desired : %s\n" +
                "[*] - Is Recursion Available : %s\n" +
                "[*] - Response Code : %s\n" +
                "[*] - Question Count : %s\n" +
                "[*] - Answer Count : %s\n" +
                "[*] - Authority Count : %s\n" +
                "[*] - Domain Name : %s\n" +
                "[*] - Query Type : %s\n" +
                "[*] - Query Class : %s\n",
                transactionId, isResponse, opcode, isAuthoritativeAnswer, isTruncated, isRecursionDesired, isRecursionAvailable, responseCode, questionCount, answerCount, authorityCount, domainName, getQueryType(queryType), getQueryClass(queryClass)));

        if(isResponse && !dnsAnswers.isEmpty()){
            result.append("[*] - DNS Answers:\n");
            for (DNSAnswer answer : dnsAnswers) {
                result.append(answer.toString()).append("\n");
            }
        }
    return result.toString();
}

class DNSAnswer {
    private String name;
    private String type;
    private String classType;
    private long ttl;
    private String data;

    public DNSAnswer(String name, String type, String classType, long ttl, String data) {
        this.name = name;
        this.type = type;
        this.classType = classType;
        this.ttl = ttl;
        this.data = data;
    }

    @Override
    public String toString() {
        return String.format("[*] - Domain Name: %s\n" +
                        "[*] - Type: %s\n" +
                        "[*] - Class: %s\n" +
                        "[*] - TTL: %d\n" +
                        "[*] - IPv4 or IPv6: %s\n",
                        name, type, classType, ttl, data);
    }
}}
