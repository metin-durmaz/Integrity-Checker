import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.sql.Timestamp;
import java.text.*;
import java.util.*;

/**
 * Second Part
 **/
public class CreateReg {

    private String regFilePath;
    private String programPath;
    private String hashFunction;
    private String privateKeyFilePath;
    private BufferedWriter logFile; // Attributes
    private byte[] hashedPassword;
    private Timestamp timestamp;
    private SimpleDateFormat dateFormat;

    /**
     * Registry file creation started.
     **/
    public CreateReg(String regFilePath, String programPath, String logFilePath, String hashFunction,
            String privateKeyFilePath) throws Exception {

        this.regFilePath = regFilePath;
        this.programPath = programPath;
        this.hashFunction = hashFunction;
        this.privateKeyFilePath = privateKeyFilePath;

        dateFormat = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
        logFile = new BufferedWriter(new FileWriter(logFilePath, true)); // Log file created
        hashedPassword = CryptFunctions.passwordGetter();
        logFileHandler();
    }

    /**
     * Decrypts the text inside the privateKeyFile. Checks if the decrypted text
     * contains meaningful text previously inserted. If it does not, it prints the
     * wrong password to logFile and terminates the program.
     **/
    private void logFileHandler() throws Exception {

        String encryptedPrivateKeyFileContent = new String(Files.readAllBytes(Paths.get(privateKeyFilePath)));
        String decryptedPrivateKeyContent = CryptFunctions.decrypt(encryptedPrivateKeyFileContent, hashedPassword);

        if (!decryptedPrivateKeyContent.endsWith("meaningful text")) {
            timestamp = new Timestamp(System.currentTimeMillis());
            logFile.write(dateFormat.format(timestamp) + ": Wrong password attempt!\n");
        } else {
            regFileHandler();
        }
        logFile.close();
    }

    /**
     * Creates the registry file. Gets the hash values of the files in the directory
     * to be monitored. Calls a function to sign the regFile by taking the hash
     * value of all the text in the regFile.
     **/
    private void regFileHandler() throws Exception {

        File file = new File(regFilePath);
        PrintWriter regFile = new PrintWriter(file);

        timestamp = new Timestamp(System.currentTimeMillis());
        logFile.write(dateFormat.format(timestamp) + ": Registry file is created at " + file.getAbsolutePath() + "\n");

        File folder = new File(programPath);
        File[] listOfFiles = folder.listFiles();
        String regFileContent = "";
        for (File f : listOfFiles) {
            String content = new String(Files.readAllBytes(Paths.get(f.getAbsolutePath())));
            regFileContent = regFileContent.concat(f.getAbsolutePath() + " "
                    + Base64.getEncoder().encodeToString(CryptFunctions.hashFunction(content, hashFunction)) + "\n");
            timestamp = new Timestamp(System.currentTimeMillis());
            logFile.write(dateFormat.format(timestamp) + ": " + f.getAbsolutePath() + " is added to registry\n");
        }
        regFileContent = regFileContent.concat(sign(CryptFunctions.hashFunction(regFileContent, hashFunction)));
        timestamp = new Timestamp(System.currentTimeMillis());
        logFile.write(dateFormat.format(timestamp) + ": " + listOfFiles.length
                + " files are added to the registry and registry creation is finished!\n");

        regFile.write(regFileContent);
        regFile.close();
    }

    /**
     * Creates private signature using SHA256withRSA. It takes the private key and
     * signs the plainText from the parameter. It prints the signature at the end of
     * the RegFile file.
     *
     * @param plainText --> Hash value of all the text in the regFile.
     * @return --> Base64 encoded signature
     **/
    private String sign(byte[] plainText) throws Exception {

        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(getPrivateKey());
        privateSignature.update(plainText);
        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    /**
     * It decrypts the encrypted text in privateKeyFile by receiving it. Extract
     * meaningful text from the resulting text. Converts the key that remains as a
     * text back to the private key form.
     *
     * @return --> Generated privateKey
     **/
    private PrivateKey getPrivateKey() throws Exception {

        String privateKeyContent = new String(Files.readAllBytes(Paths.get(privateKeyFilePath)));
        privateKeyContent = CryptFunctions.decrypt(privateKeyContent, hashedPassword);

        privateKeyContent = privateKeyContent.replace("meaningful text", "");
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));

        return kf.generatePrivate(keySpecPKCS8);
    }

}