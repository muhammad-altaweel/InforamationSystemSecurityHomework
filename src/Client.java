import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Scanner;

public class Client {
    public static void main(String args[]) throws Exception {

        //Generate Public and Private Keys for Client
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair pair = keyPairGenerator.generateKeyPair();
        PrivateKey clientPrivateKey = pair.getPrivate();
        PublicKey clientPublicKey = pair.getPublic();
        PublicKey CaPublicKey;
        X509Certificate clientCertificate;
        String clientName = "client01";
        String serverName;
        //1.Connect with CA to Get clientCertificate 2.Generate Csr and send it to CA 3.Receive Certificate from CA
        try {
            Socket socket = new Socket("localhost", 22222);
            OutputStream outputStream = socket.getOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
            InputStream inputStream = socket.getInputStream();
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
            //Receive CA public key
            CaPublicKey = (PublicKey) objectInputStream.readObject();
            //send CSR to CA
            CSR serverCsr = new CSR(clientName, clientPublicKey);
            objectOutputStream.writeObject(serverCsr);
            //Receive file directry  which contain secret message for verifying the CSR
            String filepath = (String) objectInputStream.readObject();
            String secretMessage = "";
            //read the secret Message
            File file = new File(filepath);
            BufferedReader br = new BufferedReader(new FileReader(file));
            String st;
            while ((st = br.readLine()) != null)
                secretMessage += st;
            br.close();
            //sign the secret Message with private and send it to CA
            Signature sig = Signature.getInstance("SHA256withRSA");
            SignedObject signedSecretMessage = new SignedObject(secretMessage, clientPrivateKey, sig);
            objectOutputStream.writeObject(signedSecretMessage);
            //Receive the clientCertificate from CA
            clientCertificate = (X509Certificate) objectInputStream.readObject();
            if (Verify(clientCertificate, CaPublicKey)) {
                System.out.println("Certificate Received and Verified successfully\n");
            } else {
                System.out.println("Certificate was not received or did not verified successfully");
            }
            socket.close();
            //System.out.println(clientCertificate);
        } catch (Exception e) {
            System.out.println("Could not connect with Certificate Authority");
            return;
        }

        int k = 0;
        try {//connect with the server
            Socket socket = new Socket("localhost", 11111);
            OutputStream outputStream = socket.getOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
            InputStream inputStream = socket.getInputStream();
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
            //send client certificate to server
            objectOutputStream.writeObject(clientCertificate);
            //Receive server certificate from server
            X509Certificate serverCertificate = (X509Certificate) objectInputStream.readObject();
            PublicKey serverPublicKey = serverCertificate.getPublicKey();
            //Send client Name to server
            objectOutputStream.writeObject(clientName);
            //Receive Server Name from server
            serverName = (String) objectInputStream.readObject();
            //Verify Server Certificate and server Name
            if (Verify(serverCertificate, CaPublicKey) && serverName.equals(serverCertificate.getIssuerDN().getName().substring(3))) {
                System.out.println("Server Certificate Was Verified");
                //Generate A signature Object and a SignedObject
                Signature sig = Signature.getInstance("SHA256withRSA");
                //generate session Id
                SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
                String SessionId = Base64.getEncoder().encodeToString(secretKey.getEncoded()).substring(0, 16);
                //encrypt it with server public key
                String encryptedSession = encrypt(SessionId, serverPublicKey);
                //Create a signedObject object to hold the encrypted Session Id
                SignedObject signedSession = new SignedObject(encryptedSession, clientPrivateKey, sig);
                // and send it back to server
                objectOutputStream.writeObject(signedSession);

                //Receive confirmation from server
                SignedObject signedConfirmation = (SignedObject) objectInputStream.readObject();
                boolean isConfirmationRight = signedConfirmation.verify(serverPublicKey, sig);
                String confirmation = (String) signedConfirmation.getObject();
                System.out.println("Session Id:" + SessionId);
                System.out.println("confirmation:" + decrypt(confirmation, clientPrivateKey));

                while (k != 2) {
                    //generate initialize vector and send it to server
                    String initVector = generateInitVector(SessionId.length());
                    String encInitVector = encrypt(initVector, serverPublicKey);
                    objectOutputStream.writeObject(encInitVector);
                    //  Create the request
                    Scanner scanner = new Scanner(System.in);
                    System.out.println("\nPlease Enter A new Request:");
                    System.out.println("---------------------------");
                    System.out.println("Enter the name of the file:");
                    String name = scanner.nextLine() + ".txt";
                    System.out.println("\nEnter yes if you want to modify/create the file OR no just read it:");
                    boolean isEdited = scanner.nextLine().equals("yes");
                    String text = "";
                    if (isEdited) {
                        System.out.println("\nEnter the content of the file:");
                        text = scanner.nextLine();
                    }
                    Request request = new Request(name, isEdited, text);
                    //encrypt the request
                    request.siphor(initVector, SessionId);
                    SignedObject signedRequest = new SignedObject(request, clientPrivateKey, sig);
                    //send the signed object
                    objectOutputStream.writeObject(signedRequest);
                    //Receive the signed Response
                    SignedObject signedResponse = (SignedObject) objectInputStream.readObject();
                    //Verify the Response
                    boolean b = signedRequest.verify(serverPublicKey, sig);
                    Response response = (Response) signedResponse.getObject();
                    //Decrypt the response
                    response.unSiphor(initVector, SessionId);
                    System.out.println("Message from server: " + response.getMessage());
                    if (response.getMessage().equals("file founded")) {
                        System.out.println("\nfile content ::::");
                        System.out.println(response.getText() + "\n");
                    }
                    System.out.println("Enter close if you want to close the connection or something else to continue:");
                    k = scanner.nextLine().equals("close") ? 2 : 1;
                }
                socket.close();
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    public static String encrypt(String string, PublicKey publicKey) throws Exception {
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

    public static String decrypt(String string, PrivateKey privateKey) {
        try {
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
            System.out.println(e);
        }
        return "";
    }

    private static String generateInitVector(int n) {

        // chose a Character random from this String
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                + "0123456789"
                + "abcdefghijklmnopqrstuvxyz";

        // create StringBuffer size of AlphaNumericString
        StringBuilder sb = new StringBuilder(n);

        for (int i = 0; i < n; i++) {

            int index
                    = (int) (AlphaNumericString.length()
                    * Math.random());

            // add Character one by one in end of sb
            sb.append(AlphaNumericString
                    .charAt(index));
        }

        return sb.toString();
    }

    //check if the certificate is correct compatible with a certain public key
    public static boolean Verify(X509Certificate certificate, PublicKey publicKey) {
        try {
            certificate.verify(publicKey);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
