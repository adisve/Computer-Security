package utilities;

import java.io.FileInputStream;
import java.io.IOException;

public class FileManager {

    /**
     * Return bytes read from a txt file.
     * 
     * @param path
     * @return
     * @throws IOException
     */
    public static byte[] readFile(String path) throws IOException {
        FileInputStream file = new FileInputStream(path);
        byte[] byteRead = new byte[file.available()];
        file.read(byteRead);
        file.close();
        return byteRead;
    }
}
