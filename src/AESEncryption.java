import javax.crypto.Cipher;
    import javax.crypto.SecretKey;
    import javax.crypto.SecretKeyFactory;
    import javax.crypto.spec.PBEKeySpec;
    import javax.crypto.spec.SecretKeySpec;
    import java.security.spec.KeySpec;
    import java.util.Base64;

    /*
        The Imports allow usage of classes from 'javax.crypto' package fpr AES encryption and decryption. Also for key manipulation.
     */

public class AESEncryption {

    public static void main(String[] args) throws Exception {

        String plaintext = "Hello there! I am a Text that wants to be encrypted";
        String secretKey = "ITSecurityIsFun";
        String salt = "HelloSaltValue";

        // Encrypt AES with 128-bit key
        String encrypted128 = encryptAES(plaintext, secretKey, salt, 128);
        System.out.println("Encrypted - 128-bit: " + encrypted128);

        // Decrypt AES with 128-bit key
        String decrypted128 = decryptAES(encrypted128, secretKey, salt, 128);
        System.out.println("Decrypted - 128-bit: " + decrypted128);

        // Encrypt AES with 256-bit key
        String encrypted256 = encryptAES(plaintext, secretKey, salt, 256);
        System.out.println("Encrypted (256-bit AES): " + encrypted256);

        // Decrypt AES with 256-bit key
        String decrypted256 = decryptAES(encrypted256, secretKey, salt, 256);
        System.out.println("Decrypted (256-bit AES): " + decrypted256);


        //Performance Measurements
        long startTime = System.nanoTime();
        String encrypted128_performance = encryptAES(plaintext, secretKey, salt, 128);
        long endTime = System.nanoTime();
        System.out.println("Encryption Performance Time (128-bit): " + (endTime - startTime) + " ns");

        startTime = System.nanoTime();
        String decrypted128_performance = decryptAES(encrypted128, secretKey, salt, 128);
        endTime = System.nanoTime();
        System.out.println("Decryption Performance Time (128-bit): " + (endTime - startTime) + " ns");

        startTime = System.nanoTime();
        String encrypted256_performance = encryptAES(plaintext, secretKey, salt, 256);
        endTime = System.nanoTime();
        System.out.println("Encryption Performance Time (256-bit): " + (endTime - startTime) + " ns");

        startTime = System.nanoTime();
        String decrypted256_performance = decryptAES(encrypted256, secretKey, salt, 256);
        endTime = System.nanoTime();
        System.out.println("Decryption Performance Time (256-bit): " + (endTime - startTime) + " ns");

    }

    public static String encryptAES(String plaintext, String secretKey, String salt, int keySize) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), 65536, keySize);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public static String decryptAES(String encryptedText, String secretKey, String salt, int keySize) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), 65536, keySize);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secret);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }
}
