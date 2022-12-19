package utilities;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.Mac;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Formatter;

public class Decryptor
{

    private SecretKeySpec symmetricKey;
    private IvParameterSpec iv;
    private Key privateStoreKey;
    private SecretKeySpec hashKey;
    private String hmac;
    private KeyHandle keyHandle = new KeyHandle();
    private String plainText;

    private String storePass = "lab1StorePass";
    private String privateKeyAlias = "lab1EncKeys";
    private String privateKeyPass = "lab1KeyPass";
    private String storeFileName = "src/resources/lab1Store";


    /**
     * Reads bytes in specified file. Stores symmetric key,
     * hash key and the IV value, in individual arrays.
     * 
     * Load the certificate key from the store with the help of store password,
     * alias and key password. After this, we assign symmetric key, IV and hash
     * key to our class attributes, using the decrypted result of encKey1, encKey2,
     * and encIv as inputs to each Parameter/Key-Spec creation.
     * 
     * Only works for this specific
     * file as byte ranges should technically not be hardcoded for
     * sake of reusability.
     * 
     * @param fileName
     * @throws RuntimeException
     */
    public void assignKeysAndIv(String fileName) throws RuntimeException
    {
        try
        {

            /* Slice bytes in file appropriately */
            byte[] fileBytes = FileManager.readFile(fileName);

            byte[] encKey1 = Arrays.copyOfRange(fileBytes, 0, 128);
            byte[] encKey2 = Arrays.copyOfRange(fileBytes, 256, 384);
            byte[] encIv = Arrays.copyOfRange(fileBytes, 128, 256);

            this.privateStoreKey = keyHandle.loadKey(storeFileName, storePass, privateKeyAlias, privateKeyPass.toCharArray());

            /* Symmetric key and IV value used in decrypting ciphertext data */
            this.symmetricKey = new SecretKeySpec(this.decryptRSA(encKey1, this.privateStoreKey), "AES");
            this.iv = new IvParameterSpec(this.decryptRSA(encIv, this.privateStoreKey));

            /** Creates secret key used in decryption generation of HMAC to cross-reference
             * with stored HMACs in project folder
            */
            this.hashKey = new SecretKeySpec(
				/* Decrypt stored encrypted hash key with store key (encrypted with RSA) */
                (new SecretKeySpec(this.decryptRSA(encKey2, this.privateStoreKey), "RSA")
                ).getEncoded(), 
                "HmacMD5");

        } 
        catch (IOException | UnrecoverableKeyException | CertificateException |
                 KeyStoreException | NoSuchAlgorithmException e) 
        {
            System.out.println("Error retrieving AES key/IV. Exiting");
            System.exit(0);
        }
    }

    /**
     * Computes a HMAC with the plaintext bytes and converts
     * it into a hex string that is compared with the stored Hmacs 
     * we have in the project folder.
     */
    public void generateHMAC()
    {
        Formatter formatter = new Formatter();
        try
        {
            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(this.hashKey);
            this.hmac = Utils.toHexString(mac.doFinal(this.plainText.getBytes()), formatter);
        } 
        catch (NoSuchAlgorithmException | InvalidKeyException e)
        {
            throw new RuntimeException(e);
        }
        finally
        {
            formatter.close();
        }
    }

    /**
     * Compares the two generated HMACs with the stored HMACs
     * available as plaintext, telling us which one
     * matches.
     * 
     * Instructions:
     * "Now that you have decrypted the ciphertext and it is time to calculate the message 
     * authentication code (MAC). Use key2 and your decrypted plaintext to calculate a mac. 
     * Compare your calculated mac with the two mac files (in hex string) in the .zip file. 
     * Which mac is the correct one?"
     * 
     * @param mac1Filename
     * @param mac2Filename
     */
    public void verifyMessageAuthenticationCode(String mac1Filename, String mac2Filename)
    {
        try
        {
            String hmac1 = Files.readString(Path.of(mac1Filename), StandardCharsets.UTF_8);
            String hmac2 = Files.readString(Path.of(mac2Filename), StandardCharsets.UTF_8);
            System.out.printf("HMAC 1: %s", hmac1);
            System.out.printf("\nHMAC 2: %s", hmac2);
            if (hmac1.equals(this.hmac))
            {
                System.out.printf("\n'%s' from '%s' matches generated HMAC '%s'\n", hmac1, mac1Filename, this.hmac);
            }
            else if (hmac2.equals(this.hmac))
            {
                System.out.printf("\n'%s' from '%s' matches generated HMAC '%s'\n", hmac2, mac2Filename, this.hmac);
            }
            else
                System.out.println("Generated HMAC does not match any of the two files\n");
        }
        catch (IOException e) 
        {
            throw new RuntimeException(e);
        }
    }

    /**
     * Verifies the signature of a certificate by comparing
     * it to our own computation/result.
     * 
     * Instructions:
     * As a receiver, to verify the digital signature we need to read the sender’s public key that is 
     * currently stored in the public key certificate file lab1Sign.cert. You need to read the file and 
     * then load the public key with the java class CertificateFactory, or with the command window 
     * tool ‘keytool’ (not recommended).  When you have the public key, you can check which of 
     * the two given signature files is correct. 
     * The digital signature has been signed using the SHA1withRSA algorithm, and used the 
     * plaintext and the sender’s private key as inputs. 
     * 
     * @param lab2CertificatePath
     * @param encSign1Path
     * @param encSign2Path
     */
    public void verifyDigitalSignature(String lab2CertificatePath, String encSign1Path, String encSign2Path)
    {
        try
		{
            
            /* Read the sender’s public key that is stored in the public key certificate file */
            PublicKey publicKey = keyHandle.loadCertificateKey(lab2CertificatePath);

            /* Create signature by using SHA1/RSA algorithm */
            Signature privateSignature = Signature.getInstance("SHA1withRSA");

            /* Add our store key for signing certificate */
            privateSignature.initSign((PrivateKey) this.privateStoreKey);
            /* Add plaintext resolution to signature */
            privateSignature.update(this.plainText.getBytes(StandardCharsets.UTF_8));
            privateSignature.sign();

            /* Check which signature in project folder can be verified based on our private signature */
            boolean validSignature1 = verify(privateSignature, publicKey, FileManager.readFile(encSign1Path));
            boolean validSignature2 = verify(privateSignature, publicKey, FileManager.readFile(encSign2Path));

            System.out.println("Verified signature 1: " + validSignature1);
            System.out.println("Verified signature 2: " + validSignature2);

        } 
		catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | IOException e)
		{
            throw new RuntimeException(e);
        }
    }

    /**
     * Performs verification of data with signature.
     * 
     * @param sig
     * @param publicKey
     * @param data
     * @return
     * @throws InvalidKeyException
     * @throws java.security.SignatureException
     */
    private boolean verify(Signature sig, PublicKey publicKey, byte[] data)
            throws InvalidKeyException, java.security.SignatureException
    {
        sig.initVerify(publicKey);
        sig.update(this.plainText.getBytes());
        return sig.verify(data);
    }

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
    private String getPlainText(byte[] ciphertext, SecretKeySpec symmetricKey, IvParameterSpec iv) throws RuntimeException
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
    public byte[] decryptRSA(byte[] element, Key privateStoreKey) throws RuntimeException
    {
        try
		{
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.PRIVATE_KEY, privateStoreKey);
            return decryptCipher.doFinal(element);
        } 
		catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeyException e)
		{
            System.out.println("Error decrypting element");
            throw new RuntimeException(e);
        }
    }

    /**
     * Decrypts the ciphertext into plaintext. Depends on
     * IV value and AES key to be already loaded in the class
     * attributes.
     * 
     * @param fileName
     */
    public void decryptCipherText(String fileName)
    {
        if (this.iv != null && this.symmetricKey != null)
        {
            try 
			{
                byte[] fileBytes = FileManager.readFile(fileName);
                byte[] cipherText = Arrays.copyOfRange(fileBytes, 384, fileBytes.length);
                /* Decrypt cipher text with symmetric key and IV value */
                this.plainText = this.getPlainText(cipherText, this.symmetricKey, this.iv);
                System.out.println(plainText);
            }
			catch (IOException e)
			{
                throw new RuntimeException(e);
            }
        }
        else
            System.out.println("No AES key or IV available");
    }
}
