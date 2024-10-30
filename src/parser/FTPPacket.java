package parser;


import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;


/**
 * Class used to parse and print FTP packet information.
 */
public class FTPPacket {
    private String rawData;
    private boolean checkIfFtpCommand;
    private String ftpCommand; // Command FTP detected.
    private boolean isResponse; // To know if it is a response or not.

    /**
     * Constructor of the class to initialize and parse the FTP packet from a ByteBuffer.
     * @param buffer ByteBuffer containing the FTP packet.
     * @param ftpCommand Command FTP detected.
     * @param isResponse To know if it is a response or not.
     */
    public FTPPacket(ByteBuffer buffer, String ftpCommand, boolean isResponse) {
        byte[] dataBytes = new byte[buffer.remaining()];
        buffer.get(dataBytes);

        rawData = new String(dataBytes, StandardCharsets.US_ASCII);
        this.ftpCommand = ftpCommand;
        this.isResponse = isResponse;

        // I'm checking if inside the dataBytes if there is a command FTP.

        //checkIfFtpCommand = detectAndExtractFTPCommand(rawData) != null; // If a get one FTP command it return true.
    }



    @Override
    public String toString() {
        StringBuilder result = new StringBuilder();

        if (isResponse) {
            result.append("\nFTP Response\n---------------------\n");
            result.append("[*] - FTP Response Detected\n");
            result.append("[*] - Raw Data: ").append(rawData).append("\n");
        } else if (ftpCommand != null) {
            result.append("\nFTP Command Packet\n---------------------\n");
            result.append("[*] - FTP Command: ").append(ftpCommand).append("\n");
            result.append("[*] - Raw Data: ").append(rawData).append("\n");
        }
        return result.toString();
    }
}
