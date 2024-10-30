package parser;

public class PacketUtils {

    /**
     * Convert a byte array to an ASCII string (data)
     * @param bytes Byte array containing the data.
     * @return String representation of the data.
     */
    public static String convertByteToASCII(byte[] bytes) {
        if(bytes == null) {
            return "";
        }
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            if (b >= 32 && b <= 126) {
                result.append((char) b);
            } else {
                result.append(".");
            }
        }
        return result.toString();
    }


    /**
     * Convert a byte array to a MAC address.
     * @param bytes Byte array containing the MAC address.
     * @return String representation of the MAC address.
     */

    public static String bytesToMAC(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (int i = 0 ; i < bytes.length ; i++) {
            result.append(String.format("%02X", bytes[i]));
            if (i < bytes.length - 1) { // I don't want a ':' at the end of the MAC Address
                result.append(":");
            }
        }
        return result.toString();
    }


    /**
     * Convert a byte array to an IPv4 address.
     * @param bytes Byte array containing the IPv4 address.
     * @return String representation of the IPv4 address.
     */
    public static String bytesToIPv4(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            result.append(bytes[i] & 0xFF); // 0xFF allow me to transform the signed int to unsigned int because '-' in binary signed is '1'.
            if (i < bytes.length - 1) result.append(".");
        }
        return result.toString();
    }

    /**
     * Convert a byte array to an IPv6 address.
     * @param bytes Byte array containing the IPv6 address.
     * @return String representation of the IPv6 address.
     */
    public static String bytesToIPv6(byte[] bytes) {

        // 2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF

        StringBuilder result = new StringBuilder();
        for(int i = 0; i < bytes.length; i += 2) {
            result.append(String.format("%02X%02X", bytes[i], bytes[i + 1])); // Recreate IPv6 Format.
            if(i < bytes.length - 2) {
                result.append(":");
            }
        }

        return result.toString();
    }

    /**
     * Converts a byte array to a hexadecimal string representation.
     * @param bytes Byte array to convert.
     * @return Hexadecimal string representation of the byte array.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }

}
