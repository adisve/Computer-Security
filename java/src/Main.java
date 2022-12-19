import utilities.Decryptor;

public class Main {

    public static void main(String args[])
    {
        assert args.length == 7: "Not enough arguments passed to main function";
        Decryptor decryptor = new Decryptor();

        decryptor.assignKeysAndIv(args[0]);
        System.out.println("\n-------- Cipher text decryption --------\n");
        decryptor.decryptCipherText(args[1]);
        System.out.println("\n----------------------------------------\n");
        decryptor.generateHMAC();
        System.out.println("\n-------- Hmac authentication --------\n");
        decryptor.verifyMessageAuthenticationCode(args[2], args[3]);
        System.out.println("\n-------------------------------------\n");
        System.out.println("\n-------- Digital signature verification--------\n");
        decryptor.verifyDigitalSignature(args[4], args[5], args[6]);
        System.out.println("\n-----------------------------------------------\n");
    }
}