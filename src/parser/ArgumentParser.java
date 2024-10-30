package parser;

import java.util.HashSet;
import java.util.Set;

public class ArgumentParser {
    // I use this because imagine if a user gives the same argument twice I don't want to have duplication.
    private final Set<String> arguments = new HashSet<>();

    private String specificHttpSessionKey;
    private String specificTcpStreamKey;

    public ArgumentParser(String[] args) {
        for (String arg : args) {

            if(arg.startsWith("--httpKey=")) {
                specificHttpSessionKey = arg.split("=", 2)[1]; // Get the key of the specific http session like : --httpKey=192.168.1.2:80 -> 192.168.1.1:50000 I will have at thend : '192.168.1.2:80 -> 192.168.1.1:50000'
                arguments.add("--http"); // If the user forget to add --http

            } else if (arg.startsWith("--tcpStream=")) {
                specificTcpStreamKey = arg.split("=", 2)[1]; // TCP Stream Key
                arguments.add("--tcp"); // I want to be also sure that user gave --tcp argument.
            } else if (arg.equals("--dns") || arg.equals("--dhcp") || arg.equals("--quic")) {
                arguments.add("--udp"); // I do this because if the user only put the --dns or --dhcp alone it have to parse also UDP otherwise cannot see the DNS or DHCP packets.
            } else if (arg.equals("--ftp") || arg.equals("--http")) {
                arguments.add("--tcp");
            }
            arguments.add(arg);
        }
    }

    public String getSpecificHttpSessionKey() {
        return specificHttpSessionKey;
    }

    public String getSpecificTcpStreamKey() {
        return specificTcpStreamKey;
    }

    // Functions to check if a user want to see a specific protocol.


    public boolean isTCPActivated() {
        return arguments.contains("--tcp");
    }

    public boolean isUDPActivated() {
        return arguments.contains("--udp");
    }

    public boolean isICMPActivated() {
        return arguments.contains("--icmp");
    }

    public boolean isARPActivated() {
        return arguments.contains("--arp");
    }

    public boolean isDNSActivated() {
        return arguments.contains("--dns");
    }

    public boolean isDHCPActivated() {
        return arguments.contains("--dhcp");
    }

    public boolean isFTPActivated() {
        return arguments.contains("--ftp");
    }

    public boolean isQUICActivated() {
        return arguments.contains("--quic");
    }

    public boolean isHTTPActivated() {
        return arguments.contains("--http");
    }

    public boolean isShowAllActivated() {
        return arguments.contains("--showall");
    }

}
