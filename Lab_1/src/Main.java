import Utilities.CipherHandle;
import Utilities.KeyHandle;

public class Main {

    public static void main(String[] args) {
        CipherHandle cipherHandle = new CipherHandle();

        cipherHandle.assignKeyAndIv("src/ciphertext.enc");
        cipherHandle.decryptCipherText("src/ciphertext.enc");
        cipherHandle.calculateHMAC();
        cipherHandle.compareHMAC("src/ciphertext.mac1.txt", "src/ciphertext.mac2.txt");
        cipherHandle.verifySignature("src/lab1Sign.cert", "src/ciphertext.enc.sig1", "src/ciphertext.enc.sig2");
    }
}