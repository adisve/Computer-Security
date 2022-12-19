import utilities.CipherHandle;

public class Main {

    public static void main(String args[])
    {
        assert args.length == 7: "Not enough arguments passed to main function";
        CipherHandle cipherHandle = new CipherHandle();

        cipherHandle.assignKeyAndIv(args[0]);
        System.out.println("\n-------- Cipher text decryption --------\n");
        cipherHandle.decryptCipherText(args[1]);
        System.out.println("\n----------------------------------------\n");
        cipherHandle.generateHMAC();
        System.out.println("\n-------- Hmac authentication --------\n");
        cipherHandle.verifyMessageAuthenticationCode(args[2], args[3]);
        System.out.println("\n-------------------------------------\n");
        System.out.println("\n-------- Digital signature verification--------\n");
        cipherHandle.verifyDigitalSignature(args[4], args[5], args[6]);
        System.out.println("\n-----------------------------------------------\n");
    }
}