import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;

public class CryptFunctions {

    /**
     * It was written to encrypt given text.
     *
     * @param input --> plainText
     * @param key   --> MD5 hashed password
     * @return --> cipherText
     */
    public static String encrypt(String input, byte[] key) throws Exception {

        SecretKeySpec sKeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, sKeySpec, new IvParameterSpec(key));
        byte[] cipherText = cipher.doFinal(input.getBytes());

        return Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     * It was written to decrypt given text.
     *
     * @param input --> cipherText
     * @param key   --> MD5 hashed password
     * @return --> plainText
     */
    public static String decrypt(String input, byte[] key) throws Exception {

        SecretKeySpec sKeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, sKeySpec, new IvParameterSpec(key));
        byte[] output = cipher.doFinal(Base64.getDecoder().decode(input));

        return new String(output);
    }

    /**
     * It asks the user for a password. Send to function to hash.
     *
     * @return --> MD5 hashed password
     **/
    public static byte[] passwordGetter() throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter a password : ");
        String password = scanner.nextLine();
        scanner.close();

        return CryptFunctions.hashFunction(password, "MD5");
    }

    /**
     * It was written to hash given text.
     *
     * @param text     --> Given Text
     * @param hashType --> Hash function --> MD5 or SHA-256
     * @return --> Hashed text
     */
    public static byte[] hashFunction(String text, String hashType) throws Exception {

        MessageDigest md = MessageDigest.getInstance(hashType);
        return md.digest(text.getBytes());
    }

}