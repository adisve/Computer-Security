import utilities.CipherHandle;

public class Main {

    public static void main(String args[]) {
        
        assert args.length == 7: "Not enough arguments passed to main function";

        CipherHandle cipherHandle = new CipherHandle();
        cipherHandle.assignKeyAndIv(args[0]);
        cipherHandle.decryptCipherText(args[1]);
        cipherHandle.calculateHMAC();
        cipherHandle.compareHMAC(args[2], args[3]);
        cipherHandle.verifySignature(args[4], args[5], args[6]);
    }
}