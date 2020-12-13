//import javax.crypto.*;
//import javax.crypto.spec.IvParameterSpec;
//import javax.crypto.spec.SecretKeySpec;
//import java.nio.charset.StandardCharsets;
//import java.security.*;
//import java.util.Base64;
//
//public class testing {
//    private final static String key = "aesEncryptionKey";
//    private final static String initVector = "encryptionIntVec";
//    public static void main(String args[]) throws Exception {
//
//        SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
//        String SessionId = Base64.getEncoder().encodeToString(secretKey.getEncoded());
//        System.out.println(SessionId.length());
//
//
//    }
//    public static String encrypt(String string , PublicKey publicKey) throws Exception {
//        //Encrypting
//        //Creating a Cipher object
//            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//
//            //Initializing a Cipher object
//            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//
//            //Add data to the cipher
//            byte[] input = string.getBytes();
//            cipher.update(input);
//
//            //encrypting the data
//            byte[] cipherText = cipher.doFinal();
//            String s = Base64.getEncoder().encodeToString(cipherText);
//            return s;
//    }
//
//    public static String decrypt(String string , PrivateKey privateKey) {
//        try
//        {
//            byte[] encrypted = Base64.getDecoder().decode(string);
//            //Decrypting
//            //Creating a Cipher object
//            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//            //Initializing the same cipher for decryption
//            cipher.init(Cipher.DECRYPT_MODE, privateKey);
//            //Decrypting the text
//            byte[] decipheredText = cipher.doFinal(encrypted);
//            return new String(decipheredText, StandardCharsets.UTF_8);
//        } catch (Exception e) {
//            System.out.println(e.getCause());
//        }
//        return "";
//    }
//}













/////////////////////////////////////////////////////////////
//import java.io.IOException;
//import java.io.Serializable;
//import java.security.InvalidKeyException;
//import java.security.NoSuchAlgorithmException;
//
//import javax.crypto.BadPaddingException;
//import javax.crypto.Cipher;
//import javax.crypto.IllegalBlockSizeException;
//import javax.crypto.KeyGenerator;
//import javax.crypto.NoSuchPaddingException;
//import javax.crypto.SealedObject;
//import javax.crypto.SecretKey;
//
//public class testing {
//
//    private static Cipher ecipher;
//    private static Cipher dcipher;
//
//    private static SecretKey key;
//
//    public static void main(String[] args) {
//
//        try {
//
//            // generate secret key using DES algorithm
//            key = KeyGenerator.getInstance("DES").generateKey();
//
//            ecipher = Cipher.getInstance("DES");
//            dcipher = Cipher.getInstance("DES");
//
//            // initialize the ciphers with the given key
//
//            ecipher.init(Cipher.ENCRYPT_MODE, key);
//
//            dcipher.init(Cipher.DECRYPT_MODE, key);
//
//            // create a sealed object
//
//            SealedObject sealed = new SealedObject(new SecretObject("My secret message"), ecipher);
//
//            // get the algorithm with the object has been sealed
//
//            String algorithm = sealed.getAlgorithm();
//
//            System.out.println("Algorithm " + algorithm);
//
//            // unseal (decrypt) the object
//
//            SecretObject o = (SecretObject) sealed.getObject(dcipher);
//
//            System.out.println("Original Object: " + o);
//
//        }
//        catch (NoSuchAlgorithmException e) {
//            System.out.println("No Such Algorithm:" + e.getMessage());
//            return;
//        }
//        catch (NoSuchPaddingException e) {
//            System.out.println("No Such Padding:" + e.getMessage());
//            return;
//        }
//        catch (BadPaddingException e) {
//            System.out.println("Bad Padding:" + e.getMessage());
//            return;
//        }
//        catch (InvalidKeyException e) {
//            System.out.println("Invalid Key:" + e.getMessage());
//            return;
//        }
//        catch (IllegalBlockSizeException e) {
//            System.out.println("Illegal Block:" + e.getMessage());
//            return;
//        }
//        catch (ClassNotFoundException e) {
//            System.out.println("Class Not Found:" + e.getMessage());
//            return;
//        }
//        catch (IOException e) {
//            System.out.println("I/O Error:" + e.getMessage());
//            return;
//        }
//
//    }
//
//    public static class SecretObject implements Serializable {
//
//        //private static final long serialVersionUID = -1335351770906357695L;
//
//        private final String message;
//
//        public SecretObject(String message) {
//            this.message = message;
//        }
//
//        @Override
//        public String toString() {
//            return "SecretObject [message=" + message + "]";
//        }
//
//    }
//
//}

///////////////////////////////////////////////////////////////////////////


import java.io.Serializable;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignedObject;

public class testing {
    public static void main(String[] argv) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(1024);
        KeyPair keypair = keyGen.genKeyPair();
        PrivateKey privateKey = keypair.getPrivate();
        PublicKey publicKey = keypair.getPublic();

        Serializable o = new MyClass();


        //Pack the signed Object
        Signature sig = Signature.getInstance("SHA256withRSA");
        SignedObject so = new SignedObject(o, privateKey, sig);


        //Unpack the Signed Object
        sig = Signature.getInstance("SHA256withRSA");
        boolean b = so.verify(publicKey, sig);
        System.out.println(b);
        o = (MyClass) so.getObject();
    }
}

class MyClass implements Serializable {
    String s = "my string";
    int i = 123;
    @Override
    public String toString(){
        return this.s + " " + this.i;
    }
}