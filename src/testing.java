import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class testing {
    private final static String key = "aesEncryptionKey";
    private final static String initVector = "encryptionIntVec";
    public static void main(String args[]) throws Exception {

        // generate session key
        SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
        // get base64 encoded version of the key
        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        System.out.println(encodedKey);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair pair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
//        String k = "my string ";
//        System.out.println(k);
//        k = encrypt(k,publicKey);
//        System.out.println(k);
//        k = decrypt(k,privateKey);
//        System.out.println(k);

    }
    public static String encrypt(String string , PublicKey publicKey) throws Exception {
        //Encrypting
        //Creating a Cipher object
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            //Initializing a Cipher object
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            //Add data to the cipher
            byte[] input = string.getBytes();
            cipher.update(input);

            //encrypting the data
            byte[] cipherText = cipher.doFinal();
            String s = Base64.getEncoder().encodeToString(cipherText);
            return s;
    }

    public static String decrypt(String string , PrivateKey privateKey) {
        try
        {
            byte[] encrypted = Base64.getDecoder().decode(string);
            //Decrypting
            //Creating a Cipher object
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            //Initializing the same cipher for decryption
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            //Decrypting the text
            byte[] decipheredText = cipher.doFinal(encrypted);
            return new String(decipheredText, StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.out.println(e.getCause());
        }
        return "";
    }
}
