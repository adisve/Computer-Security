package utilities;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class Decryption {

    /**
     * Decrypt ciphertext, given the secret key and IV value.
     * 
     * @param ciphertext
     * @param key
     * @param iv
     * @return
     * @throws RuntimeException
     */
    public String decryptCipherText(byte[] ciphertext, SecretKeySpec key, IvParameterSpec iv) throws RuntimeException
    {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            byte[] plainTextBytes = cipher.doFinal(ciphertext);
            return new String(plainTextBytes, StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            System.out.println("Error deciphering ciphertext");
            throw new RuntimeException(e);
        }
    }

    /**
     * Decrypt specified byte array with the help
     * of private key.
     * 
     * @param element
     * @param privateKey
     * @return
     * @throws RuntimeException
     */
    public byte[] decryptRSA(byte[] element, Key privateKey) throws RuntimeException {
        try {
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.PRIVATE_KEY, privateKey);
            return decryptCipher.doFinal(element);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeyException e) {
            System.out.println("Error decrypting element");
            throw new RuntimeException(e);
        }
    }
}
