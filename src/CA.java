import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V1CertificateGenerator;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Date;
import java.util.LinkedList;
import java.security.cert.X509Certificate;

public class CA {
    private static String ValidityFilePath=".\\Validator\\";
    private static String ValidityFileName="theFile.txt";
    public static void main(String args[]) throws Exception
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair pair = keyPairGenerator.generateKeyPair();
        PrivateKey CAPrivateKey = pair.getPrivate();
        PublicKey CAPublicKey = pair.getPublic();
        Signature sig = Signature.getInstance("SHA256withRSA");
        LinkedList<X509Certificate> certificates = new LinkedList<X509Certificate>();

        try (ServerSocket listener = new ServerSocket(22222))
        {
            System.out.println("Certificate Authority server is running...");
            while (true)
            {
                try(Socket socket = listener.accept()){
                    OutputStream outputStream = socket.getOutputStream();
                    ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
                    InputStream inputStream = socket.getInputStream();
                    ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
                    CSR csrRequest;
                    //Send public key
                    objectOutputStream.writeObject(CAPublicKey);
                    //Receive CSR
                    csrRequest = (CSR) objectInputStream.readObject();
                    //Generate random text and send it someway to the client
                    String secretMessage = generateRandomString(10);
                    objectOutputStream.writeObject(ValidityFilePath+ValidityFileName);
                    //Receive signed secret Message
                    SignedObject signedSecretMessage = (SignedObject)objectInputStream.readObject();
                    //verify the signedSecretMessage
                    String RecievedSecretMessage = (String) signedSecretMessage.getObject();
                    if(signedSecretMessage.verify(csrRequest.getPublicKey(),sig) && secretMessage.equals(RecievedSecretMessage))
                    {
                        System.out.println("The request from "+csrRequest.getName()+" Was Verified");
                        //Create the Certificate ,Sign it and send it to the client
                        X509Certificate certificate = generateCertificate(csrRequest,CAPrivateKey);
                        objectOutputStream.writeObject(certificate);
                        String Name = certificate.getIssuerDN().getName().substring(3);
                        System.out.println("Certificate to "+Name + " Was given");
                    }
                    else{
                        System.out.println("something went Wrong");
                    }
                    socket.close();
                }
                catch(Exception e){
                    System.out.println(e);
                }
            }
        }
    }
    private static String generateRandomString(int n)
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
            FileWriter fileWriter = new FileWriter(ValidityFilePath+ValidityFileName);
            PrintWriter printWriter = new PrintWriter(fileWriter);
            printWriter.print(stringGenerated);
            printWriter.close();
        } catch (Exception e) {
            System.out.println(e);
        }
        return stringGenerated;
    }
    public static X509Certificate generateCertificate(CSR csrRequest, PrivateKey privateKey)
            throws InvalidKeyException, SignatureException {
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

    //check if the certificate is correct compatible with a certain public key
    public static boolean Verify(X509Certificate certificate,PublicKey publicKey) {
        try {
            certificate.verify(publicKey);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

}
