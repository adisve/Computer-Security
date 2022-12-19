package utilities;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class Decryption {

    /**
     * Decrypt ciphertext, given the symmetric key and 
     * initialization vector value.
     * 
     * @param ciphertext
     * @param symmetricKey
     * @param iv
     * @return
     * @throws RuntimeException
     */
    public String decryptCipherText(byte[] ciphertext, SecretKeySpec symmetricKey, IvParameterSpec iv) throws RuntimeException
    {
        try
        {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, symmetricKey, iv);
            byte[] plainTextBytes = cipher.doFinal(ciphertext);
            return new String(plainTextBytes, StandardCharsets.UTF_8);
        } 
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException | InvalidKeyException e)
        {
            System.out.println("Error deciphering ciphertext");
            throw new RuntimeException(e);
        }
    }

    /**
     * Decrypt specified byte array with the help
     * of private store key.
     * 
     * @param element
     * @param privateStoreKey
     * @return
     * @throws RuntimeException
     */
    public byte[] decryptRSA(byte[] element, Key privateStoreKey) throws RuntimeException {
        try {
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.PRIVATE_KEY, privateStoreKey);
            return decryptCipher.doFinal(element);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeyException e) {
            System.out.println("Error decrypting element");
            throw new RuntimeException(e);
        }
    }
}
