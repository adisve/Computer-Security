package utilities;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class KeyHandle
{

    /**
     * Load private key from keystore with the help of 
     * store password, alias and key password.
     * 
     * Keystores and truststores are repositories that 
     * contain cryptographic artifacts like certificates 
     * and private keys that are used for cryptographic 
     * protocols (such as TLS). 
     * 
     * @param storeFilename
     * @param storePassword
     * @param storeAlias
     * @param keyPassword
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    public Key loadKey(String storeFilename, String storePassword, String storeAlias, char[] keyPassword)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException
    {
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        FileInputStream file = new FileInputStream(storeFilename);
        store.load(file, storePassword.toCharArray());
        file.close();
        return store.getKey(storeAlias, keyPassword);
    }

    /**
     * Loads the public key from the specified certificate.
     * 
     * @param fileName
     * @return
     * @throws RuntimeException
     */
    public PublicKey loadCertificateKey(String fileName) throws RuntimeException
    {
        try {
            FileInputStream file = new FileInputStream(fileName);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate)factory.generateCertificate(file);
            return certificate.getPublicKey();
        } catch (CertificateException | FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}
