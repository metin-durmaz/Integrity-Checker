import java.io.*;
import java.security.*;
import java.util.*;

/**
 * First Part
 **/
public class CreateCert {

    private byte[] hashedPassword;
    private String privateKeyFilePath; // Attributes
    private String publicKeyCertificatePath;

    /**
     * Certificate creation started.
     **/
    public CreateCert(String privateKeyFilePath, String publicKeyCertificatePath) throws Exception {
        this.privateKeyFilePath = privateKeyFilePath;
        this.publicKeyCertificatePath = publicKeyCertificatePath;

        hashedPassword = CryptFunctions.passwordGetter();
        keyToolExecutor();
        encryptedPrivateKeyFileCreator();
    }

    /**
     * Runs the functions in the keytool library through the terminal. KeyPair file
     * with .jks extension is created with the -genkey command. Certificate file
     * with .cer extension is created with the -export command.
     **/
    private void keyToolExecutor() throws Exception {

        String[] keyPairCommand = { "keytool", "-genkey", "-alias", "keyStore", "-keyalg", "RSA", "-keystore",
                "keyStore.jks", "-keypass", "metindurmaz", "-storepass", "metindurmaz", "-keysize", "2048", "-validity",
                "365", "-dname", "CN=metin, OU=metin, O=metin, L=metin, S=metin, C=metin" };
        Process keyPairProcess = Runtime.getRuntime().exec(keyPairCommand);
        keyPairProcess.waitFor();

        String[] certCommand = { "keytool", "-export", "-alias", "keyStore", "-storepass", "metindurmaz", "-keystore",
                "keyStore.jks", "-rfc", "-file", publicKeyCertificatePath };
        Process certProcess = Runtime.getRuntime().exec(certCommand);
        certProcess.waitFor();
    }

    /**
     * Creates the privateKeyFile file. It takes the private key and adds meaningful
     * text over it. Encrypts the generated text with the password requested from
     * the user.
     **/
    private void encryptedPrivateKeyFileCreator() throws Exception {

        BufferedWriter privateKeyFile = new BufferedWriter(new FileWriter(privateKeyFilePath));

        String privateKeyContent = Base64.getEncoder().encodeToString(getPrivateKey().getEncoded()) + "meaningful text";
        privateKeyFile.write(CryptFunctions.encrypt(privateKeyContent, hashedPassword));
        privateKeyFile.close();
    }

    /**
     * It takes the private key from the keyStore file with .jks extension.
     *
     * @return --> privateKey
     **/
    private PrivateKey getPrivateKey() throws Exception {
        FileInputStream in = new FileInputStream("keyStore.jks");
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(in, "metindurmaz".toCharArray());
        return (PrivateKey) (keyStore.getKey("keyStore", "metindurmaz".toCharArray()));
    }

}