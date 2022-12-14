import utilities.CipherHandle;

public class Main {

    public static void main(String[] args) {
        CipherHandle cipherHandle = new CipherHandle();

        cipherHandle.assignKeyAndIv("src/resources/ciphertext.enc");
        cipherHandle.decryptCipherText("src/resources/ciphertext.enc");
        cipherHandle.calculateHMAC();
        cipherHandle.compareHMAC("src/resources/ciphertext.mac1.txt", "src/resources/ciphertext.mac2.txt");
        cipherHandle.verifySignature("src/resources/lab1Sign.cert", "src/resources/ciphertext.enc.sig1", "src/resources/ciphertext.enc.sig2");
    }
}