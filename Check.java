import java.util.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.text.*;
import java.sql.Timestamp;

/**
 * Third Part
 **/
public class Check {
    private Timestamp timestamp;
    private SimpleDateFormat dateFormat;
    private BufferedWriter logFile;
    private String regFilePath; // Attributes
    private String programPath;
    private String hashFunction;
    private String certificatePath;

    /**
     * Check process started.
     **/
    public Check(String regFilePath, String programPath, String logFilePath, String hashFunction,
            String certificatePath) throws Exception {

        this.regFilePath = regFilePath;
        this.programPath = programPath;
        this.hashFunction = hashFunction;
        this.certificatePath = certificatePath;

        logFile = new BufferedWriter(new FileWriter(logFilePath, true));
        dateFormat = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
        checkOperation();
    }

    /**
     * Checks whether the regFile file has been changed with the checkSign() method.
     * If it has been changed, it will print the verification failed and terminate
     * the program. It checks that the files in the location to be monitored are
     * changed, deleted or new files are created with the isFile ... functions. If
     * there is no change, it prints that there is no change.
     **/
    private void checkOperation() throws Exception {

        if (!checkSign()) {
            timestamp = new Timestamp(System.currentTimeMillis());
            logFile.write(dateFormat.format(timestamp) + ": Registry file verification failed!\n");
            logFile.close();
            System.exit(0);
        }

        boolean isFileCreated = isFileCreated(getNewFiles(), getOldFiles());
        boolean isFileDeleted = isFileDeleted(getNewFiles(), getOldFiles());
        boolean isFileAltered = isFileAltered(getNewFiles(), getOldFiles());

        if (!isFileCreated && !isFileDeleted && !isFileAltered) {
            timestamp = new Timestamp(System.currentTimeMillis());
            logFile.write(dateFormat.format(timestamp) + ": The directory is checked and no change is detected!\n");
        }
        logFile.close();
    }

    /**
     * RegFile content received. Signature content received. PublicKey has been
     * received. Sent to verify() function for verification.
     *
     * @return --> Whether the contents of the regFile file has changed
     */
    private boolean checkSign() throws Exception {

        byte[] regFileDigest = getRegFile();
        String sign = getSign();
        PublicKey publicKey = getPublicKey();
        return verify(regFileDigest, sign, publicKey);
    }

    /**
     * RegFile file contents received The content was hashed and sent.
     *
     * @return --> Hashed regFile content.
     **/
    private byte[] getRegFile() throws Exception {

        String[] regFileArray = (new String(Files.readAllBytes(Paths.get(regFilePath)))).split("\n");
        String regFile = "";
        for (int i = 0; i < regFileArray.length - 1; i++) {
            regFile = regFile.concat(regFileArray[i] + "\n");
        }
        return CryptFunctions.hashFunction(regFile, hashFunction);
    }

    /**
     * Signature was obtained by going to the last line of the regFile.
     *
     * @return --> Signature in string form
     **/
    private String getSign() throws Exception {

        Scanner scanner = new Scanner(new File(regFilePath));
        String sign = "";
        while (scanner.hasNextLine()) {
            sign = scanner.nextLine();
        }
        scanner.close();
        return sign;
    }

    /**
     * A certificate instance was created using the certificate path. The publicKey
     * was accessed from within the instance.
     *
     * @return --> publicKey
     **/
    private PublicKey getPublicKey() throws Exception {

        FileInputStream in = new FileInputStream(certificatePath);
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(in);
        return certificate.getPublicKey();
    }

    /**
     * Signature verification was made with the incoming parameters.
     *
     * @param plainText --> Hashed regFile content
     * @param signature --> Signature from the last line of the regFile
     * @param publicKey --> publicKey, taken from the certificate file
     * @return --> Boolean value indicating whether the file has been verified or
     *         not
     **/
    private boolean verify(byte[] plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText);

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    /**
     * It was written to keep old files. The file name and hash values were obtained
     * by accessing the contents of the regFile. The file name and hash values were
     * kept using the LinkedHashMap structure.
     *
     * @return --> LinkedHashMap oldFiles
     **/
    private LinkedHashMap<String, String> getOldFiles() throws Exception {

        String[] regFile = (new String(Files.readAllBytes(Paths.get(regFilePath)))).split("\n");
        LinkedHashMap<String, String> oldFiles = new LinkedHashMap<>();
        for (int i = 0; i < regFile.length - 1; i++) {
            String[] s = regFile[i].split(" ");
            String path = new String();
            for (int j = 0; j < s.length - 1; j++)
                path = path.concat(s[j] + " ");
            oldFiles.put(path.trim(), s[s.length - 1]);
        }
        return oldFiles;
    }

    /**
     * It was written to get new files. It gets the files in the directory to be
     * monitored. Puts the file names and hashes of the files in the LinkedHashMap
     * structure
     *
     * @return --> LinkedHashMap newFiles.
     **/
    private LinkedHashMap<String, String> getNewFiles() throws Exception {

        File folder = new File(programPath);
        File[] listOfFiles = folder.listFiles();
        LinkedHashMap<String, String> newFiles = new LinkedHashMap<>();

        for (File f : listOfFiles) {
            String content = new String(Files.readAllBytes(Paths.get(f.getAbsolutePath())));
            String hash = Base64.getEncoder().encodeToString(CryptFunctions.hashFunction(content, hashFunction));
            newFiles.put(f.getAbsolutePath(), hash);
        }

        return newFiles;
    }

    /**
     * It compares the hashes of new files with the hashes of old files. If there is
     * a hash value found in new files but not in old files, it indicates that the
     * new file has been created.
     * 
     * @param newFiles --> LinkedHashMap that contains newFiles
     * @param oldFiles --> LinkedHashMap that contains newFiles
     * @return --> Indicates whether a new file has been created
     */
    private boolean isFileCreated(LinkedHashMap<String, String> newFiles, LinkedHashMap<String, String> oldFiles)
            throws Exception {

        boolean flag = false;
        for (String s : newFiles.keySet()) {
            if (!oldFiles.containsKey(s)) {
                timestamp = new Timestamp(System.currentTimeMillis());
                logFile.write(dateFormat.format(timestamp) + ": " + s + " is created\n");
                flag = true;
            }
        }
        return flag;
    }

    /**
     * It compares the hashes of new files with the hashes of old files. If there is
     * a hash value found in old files but not in new files, it indicates that a
     * file has been deleted.
     *
     * @param newFiles --> LinkedHashMap that contains newFiles
     * @param oldFiles --> LinkedHashMap that contains newFiles
     * @return --> Indicates whether a file has been deleted
     */
    private boolean isFileDeleted(LinkedHashMap<String, String> newFiles, LinkedHashMap<String, String> oldFiles)
            throws Exception {

        boolean flag = false;
        for (String s : oldFiles.keySet()) {
            if (!newFiles.containsKey(s)) {
                timestamp = new Timestamp(System.currentTimeMillis());
                logFile.write(dateFormat.format(timestamp) + ": " + s + " is deleted\n");
                flag = true;
            }
        }
        return flag;
    }

    /**
     * It compares the hashes of new files with the hashes of old files. If the hash
     * value of an old file with the same name is not found in a new file with the
     * same name, this indicates that the file has been altered.
     *
     * @param newFiles --> LinkedHashMap that contains newFiles
     * @param oldFiles --> LinkedHashMap that contains newFiles
     * @return --> Indicates whether a file has been altered
     */
    private boolean isFileAltered(LinkedHashMap<String, String> newFiles, LinkedHashMap<String, String> oldFiles)
            throws Exception {

        boolean flag = false;
        for (String s : oldFiles.keySet()) {
            if (newFiles.containsKey(s) && !newFiles.get(s).equals(oldFiles.get(s))) {
                timestamp = new Timestamp(System.currentTimeMillis());
                logFile.write(dateFormat.format(timestamp) + ": " + s + " is altered\n");
                flag = true;
            }
        }
        return flag;
    }

}