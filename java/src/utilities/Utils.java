package utilities;

import java.util.Formatter;

public class Utils {
    /**
     * Converts byte array to hex string representation.
     * 
     * @param bytes
     * @param formatter
     * @return
     */
    public static String toHexString(byte[] bytes, Formatter formatter)
    {
        
        for (byte b : bytes) {
            formatter.format("%02x", b);
        }
        String res = formatter.toString();
        formatter.close();
        return res;
    }
}
