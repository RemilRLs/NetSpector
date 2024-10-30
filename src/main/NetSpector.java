package main;
import parser.PcapFileReader;
import parser.ArgumentParser;

public class NetSpector {
    public static void main(String[] args) {
        ArgumentParser argumentParser = new ArgumentParser(args);
        PcapFileReader pcapReader = new PcapFileReader(argumentParser);


        if (args.length < 2 || args[0].equals("-h") || args[0].equals("--help")) {
            printHelp();
            return;
        }

        // If users didn't put the option -f.
        if (!args[0].equals("-f")) {
            System.err.println("[X] - Error : You must use the -f option to provide a .pcap type file");
            printHelp();
            return;
        }

        String filePath = args[1];

        // Verification that the user provides a .pcap file.
        if(!filePath.contains(".pcap")) {
            System.err.println("[X] - Error : You did not provide a .pcap file");
            return;
        }


        pcapReader.analyzePcapFile(filePath);

    }

    /**
     * Displays a help message for using NetSpector
     */
    private static void printHelp() {
        System.out.println("Usage : java PcapReader -f <file.pcap>");
        System.out.println("Example : java PcapReader -f arp.pcap");
        System.out.println("Options :");
        System.out.println("  -f <file>     Specifies the PCAP file to analyze");
        System.out.println("  --tcp         Only display TCP packets");
        System.out.println("  --udp         Only display UDP packets");
        System.out.println("  --dns         Only display DNS packets");
        System.out.println("  --ftp         Only display FTP packets");
        System.out.println("  --arp         Only display ARP packets");
        System.out.println("  --icmp        Only display ICMP packets");
        System.out.println("  --ipv4        Only display IPv4 packets");
        System.out.println("  --ipv6        Only display IPv6 packets");
        System.out.println("  --dhcp        Only display DHCP packets");
        System.out.println("  --quic        Only display QUIC packets");
        System.out.println("  --http        Only display HTTP packets (with Stream)");

        System.out.println("  --tcpStream=\"<srcIP:srcPort-destIP:destPort>\" ");
        System.out.println("  -h, --help    Allows you to display all commands and parameters.");
    }



}