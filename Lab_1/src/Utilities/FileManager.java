package Utilities;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class FileManager {
    public static byte[] readFile(String path) throws IOException {
        FileInputStream file = new FileInputStream(path);
        byte[] byteRead = new byte[file.available()];
        file.read(byteRead);
        file.close();
        return byteRead;
    }
}
