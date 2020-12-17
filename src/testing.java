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

//
//import java.io.Serializable;
//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.security.Signature;
//import java.security.SignedObject;
//
//
//public class testing {
//    public static void main(String[] argv) throws Exception {
//        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
//        keyGen.initialize(1024);
//        KeyPair keypair = keyGen.genKeyPair();
//        PrivateKey privateKey = keypair.getPrivate();
//        PublicKey publicKey = keypair.getPublic();
//
//        Serializable o = new MyClass();
//
//
//        //Pack the signed Object
//        Signature sig = Signature.getInstance("SHA256withRSA");
//        SignedObject so = new SignedObject(o, privateKey, sig);
//
//
//        //Unpack the Signed Object
//        sig = Signature.getInstance("SHA256withRSA");
//        boolean b = so.verify(publicKey, sig);
//        System.out.println(b);
//        o = (MyClass) so.getObject();
//    }
//}
//
//class MyClass implements Serializable {
//    String s = "my string";
//    int i = 123;
//    @Override
//    public String toString(){
//        return this.s + " " + this.i;
//    }
//}


//
//import java.io.ByteArrayInputStream;
//import java.io.IOException;
//import java.math.BigInteger;
//import java.security.GeneralSecurityException;
//import java.security.InvalidKeyException;
//import java.security.NoSuchAlgorithmException;
//import java.security.NoSuchProviderException;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.security.SecureRandom;
//import java.security.SignatureException;
//import java.security.cert.CertificateEncodingException;
//import java.security.cert.CertificateParsingException;
//import java.security.cert.X509Certificate;
//import java.util.Date;
//import java.util.Iterator;
//
//import java.security.*;
//import java.security.cert.X509Certificate;
//import javax.security.auth.x500.X500Principal;
//
//
//import org.bouncycastle.asn1.x509.X509Name;
//import org.bouncycastle.jce.X509Principal;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.x509.X509V1CertificateGenerator;
//
//class testing
//{
//    private X509Certificate certificate;
//
//    public static X509Certificate generateV1Certificate(PublicKey publicKey, PrivateKey privateKey, String Name)
//            throws InvalidKeyException, SignatureException
//    {
//        // generate the certificate
//        //Security.addProvider(new BouncyCastleProvider());
//        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
//        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
//        certGen.setIssuerDN(new X509Principal("CN=SERVER"));
//        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
//        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
//        certGen.setSubjectDN(new X509Name("CN=" + Name));
//        certGen.setPublicKey(publicKey);
//
//// i get error here
//        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
//
//        return certGen.generateX509Certificate(privateKey);
//    }
//
//}




import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V1CertificateGenerator;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;

class testing{
    public static void main(String [] args) throws Exception{
        HashMap< String, LinkedList<String> > map = new HashMap< String, LinkedList<String>>();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair pair = keyPairGenerator.generateKeyPair();
        PrivateKey CAPrivateKey = pair.getPrivate();
        PublicKey CAPublicKey = pair.getPublic();
        CSR testCSR = new CSR("thisName",CAPublicKey);
        X509Certificate certificate = generateCertificate(testCSR,CAPrivateKey);
        System.out.println(certificate);
//        System.out.println(Verify(certificate,certificate.getPublicKey()));
//        System.out.println(certificate.getSubjectDN().toString());
        String testName = certificate.getIssuerDN().getName();
        testName = testName.substring(3,testName.length());
        System.out.println(testName);
    }
    public static X509Certificate generateCertificate(CSR csrRequest, PrivateKey privateKey)
            throws InvalidKeyException, NoSuchProviderException, SignatureException {
        PrivateKey PVK = privateKey;
        String Name = csrRequest.getName();
        PublicKey PK = csrRequest.getPublicKey();
        // generate the certificate
        Security.addProvider(new BouncyCastleProvider());
        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(new X509Principal("CN="+Name));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(new X509Name("CN=" + "test"));

        certGen.setPublicKey(PK);
        certGen.setSignatureAlgorithm("SHA256withRSA");
        return certGen.generateX509Certificate(PVK);
    }

    //check if the certificate is correct compatable with a certain public key
    public static boolean Verify(X509Certificate certificate,PublicKey publicKey) {
        try {
            certificate.verify(publicKey);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static void  addToMap(HashMap< String, LinkedList<String> >map,String userId,String newDocument){
        if(map.containsKey(userId))
            map.get(userId).add(newDocument);
        else
        {
            LinkedList<String> linkedList = new LinkedList<String>();
            linkedList.add(newDocument);
            map.put(userId,linkedList);
        }
    }
    public static boolean hasAuthrorization(HashMap< String, LinkedList<String> >map,String userId,String documentName){
        if(map.containsKey(userId))
            for(String k : map.get(userId)){
                if(k.equals(documentName))
                    return true;
            }
        return false;
    }
    private static void generateRandomString(int n)
    {
        // chose a Character random from this String
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                + "0123456789"
                + "abcdefghijklmnopqrstuvxyz";

        // create StringBuffer size of AlphaNumericString
        StringBuilder sb = new StringBuilder(n);

        for (int i = 0; i < n; i++) {

            int index
                    = (int)(AlphaNumericString.length()
                    * Math.random());

            // add Character one by one in end of sb
            sb.append(AlphaNumericString
                    .charAt(index));
        }

        String stringGenerated=sb.toString();
        try {
            FileWriter fileWriter = new FileWriter(".\\Validator\\theFile.txt");
            PrintWriter printWriter = new PrintWriter(fileWriter);
            printWriter.print(stringGenerated);
            printWriter.close();
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}


