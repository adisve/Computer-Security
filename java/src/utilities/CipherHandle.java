package utilities;

import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Formatter;


public class CipherHandle {
    private SecretKeySpec AES_KEY;
    private IvParameterSpec IV;
    private Key PRIVATE_KEY_1;
    private Key PRIVATE_KEY_2;
    private String HMAC;
    private Decryption decryption = new Decryption();
    private KeyHandle keyHandle = new KeyHandle();
    private String plainText;

    private String storePass = "lab1StorePass";
    private String privateKeyAlias = "lab1EncKeys";
    private String privateKeyPass = "lab1KeyPass";
    private String storeFileName = "src/resources/lab1Store";

    /**
     * Reads bytes in specified file. Stores first encryption key,
     * second encryption key and the IV in individual arrays. Then,
     * load the private key from the store with the help of store password,
     * alias and key password. After this, we assign AES key, IV and Private
     * key 1 to class attributes, using the decrypted result of encKey1, encKey2,
     * and encIv as inputs to each Parameter/Key-Spec creation.
     * 
     * Only works for this specific
     * file as byte ranges should technically not be hardcoded for
     * sake of reusability.
     * @param fileName
     * @throws RuntimeException
     */
    public void assignKeyAndIv(String fileName) throws RuntimeException {
        try {
            byte[] fileBytes = FileManager.readFile(fileName);

            byte[] encKey1 = Arrays.copyOfRange(fileBytes, 0, 128);
            byte[] encKey2 = Arrays.copyOfRange(fileBytes, 256, 384);
            byte[] encIv = Arrays.copyOfRange(fileBytes, 128, 256);

            this.PRIVATE_KEY_1 = keyHandle.loadKey(storeFileName, storePass, privateKeyAlias, privateKeyPass.toCharArray());

            this.AES_KEY = new SecretKeySpec(decryption.decryptRSA(encKey1, this.PRIVATE_KEY_1), "AES");
            this.IV = new IvParameterSpec(decryption.decryptRSA(encIv, this.PRIVATE_KEY_1));
            this.PRIVATE_KEY_2 = new SecretKeySpec(decryption.decryptRSA(encKey2, this.PRIVATE_KEY_1), "RSA");

        } catch (IOException | UnrecoverableKeyException | CertificateException |
                 KeyStoreException | NoSuchAlgorithmException e) {
            System.out.println("Error retrieving AES key and IV. Exiting");
            System.exit(0);
        }
    }

    /**
     * Decrypt the ciphertext into plaintext. Depends on
     * IV value and AES key to be already loaded in the class
     * attributes.
     * 
     * @param fileName
     */
    public void decryptCipherText(String fileName)
    {
        if (this.IV != null && this.AES_KEY != null)
        {
            try {
                byte[] fileBytes = FileManager.readFile(fileName);
                byte[] cipherText = Arrays.copyOfRange(fileBytes, 384, fileBytes.length);
                this.plainText = decryption.decryptCipherText(cipherText, this.AES_KEY, this.IV);
                System.out.println(plainText);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        else
            System.out.println("No AES key or IV available for handle");
    }

    /**
     * Converts byte array to hex string representation.
     * 
     * @param bytes
     * @param formatter
     * @return
     */
    private static String toHexString(byte[] bytes, Formatter formatter)
    {
        
        for (byte b : bytes) {
            formatter.format("%02x", b);
        }
        String res = formatter.toString();
        formatter.close();
        return res;
    }

    /**
     * Creates secret key from private key 2 bytes and HmacMD5
     * hashing algorithm. We then can compute the Hmac with the
     * plaintext bytes and convert it into a hex string to compare
     * with the stored Hmacs we have in the project.
     */
    public void calculateHMAC()
    {
        SecretKeySpec secretKeySpec = new SecretKeySpec(this.PRIVATE_KEY_2.getEncoded(), "HmacMD5");
        Formatter formatter = new Formatter();
        try {
            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(secretKeySpec);
            this.HMAC = toHexString(mac.doFinal(this.plainText.getBytes()), formatter);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        } finally {
            formatter.close();
        }
    }

    /**
     * Compares the computed Hmacs with the stored Hmacs
     * available as plaintext, telling us which one
     * matches.
     * 
     * @param fileName1
     * @param fileName2
     */
    public void compareHMAC(String fileName1, String fileName2)
    {
        try {
            String hmac1 = Files.readString(Path.of(fileName1), StandardCharsets.UTF_8);
            String hmac2 = Files.readString(Path.of(fileName2), StandardCharsets.UTF_8);
            System.out.printf("\nHMAC 1: %s", hmac1);
            System.out.printf("\nHMAC 2: %s", hmac2);
            if (hmac1.equals(this.HMAC))
            {
                System.out.printf("\n%s from %s matches generated HMAC %s\n", hmac1, fileName1, this.HMAC);
            }
            else if (hmac2.equals(this.HMAC))
            {
                System.out.printf("\n%s from %s matches generated HMAC %s\n", hmac2, fileName2, this.HMAC);
            }
            else
                System.out.println("Generated HMAC does not match any of the two files\n");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Verifies the signature of a certificate by comparing
     * to our own computation/result.
     * 
     * @param lab1SignaturePath
     * @param encSign1Path
     * @param encSign2Path
     */
    public void verifySignature(String lab1SignaturePath, String encSign1Path, String encSign2Path)
    {
        try {
            // Get public key from certificate
            PublicKey publicKey = keyHandle.loadCertificateKey(lab1SignaturePath);
            // Create signature
            Signature privateSignature = Signature.getInstance("SHA1withRSA");
            privateSignature.initSign((PrivateKey) this.PRIVATE_KEY_1);
            privateSignature.update(this.plainText.getBytes(StandardCharsets.UTF_8));
            privateSignature.sign();

            // Verify
            boolean resSig1 = doVerify(privateSignature, publicKey, FileManager.readFile(encSign1Path));
            boolean resSig2 = doVerify(privateSignature, publicKey, FileManager.readFile(encSign2Path));

            System.out.println("VERIFIED SIGNATURE 1: " + resSig1);
            System.out.println("VERIFIED SIGNATURE 2: " + resSig2);

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | IOException e) {
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
    private boolean doVerify(Signature sig, PublicKey publicKey, byte[] data)
            throws InvalidKeyException, java.security.SignatureException {
        sig.initVerify(publicKey);
        sig.update(this.plainText.getBytes());
        return sig.verify(data);
    }
}
