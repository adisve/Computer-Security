package Utilities;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Formatter;

import static javax.xml.crypto.dsig.SignatureMethod.HMAC_SHA512;

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
    private String storeFileName = "src/lab1Store";
    private String cipherText = "src/ciphertext.enc";

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
        {
            System.out.println("No AES key or IV available for handle");
        }
    }

    private static String toHexString(byte[] bytes)
    {
        Formatter formatter = new Formatter();
        for (byte b : bytes) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    public void calculateHMAC()
    {
        SecretKeySpec secretKeySpec = new SecretKeySpec(this.PRIVATE_KEY_2.getEncoded(), "HmacMD5");
        try {
            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(secretKeySpec);
            this.HMAC = toHexString(mac.doFinal(this.plainText.getBytes()));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

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

    private boolean doVerify(Signature sig, PublicKey publicKey, byte[] data)
            throws InvalidKeyException, java.security.SignatureException {
        sig.initVerify(publicKey);
        sig.update(this.plainText.getBytes());
        return sig.verify(data);
    }
}
