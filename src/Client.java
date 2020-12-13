import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
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


        int k = 0;
            try {
                Socket socket = new Socket("localhost", 11111);
                OutputStream outputStream = socket.getOutputStream();
                ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
                //send public key to server
                objectOutputStream.writeObject(clientPublicKey);
                InputStream inputStream = socket.getInputStream();
                ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
                //Receive public key from server
                PublicKey serverPublicKey = (PublicKey)objectInputStream.readObject();
                //Generate A signature Object and a SignedObject
                Signature sig = Signature.getInstance("SHA256withRSA");
                //generate session Id
                SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
                String SessionId = Base64.getEncoder().encodeToString(secretKey.getEncoded()).substring(0,16);
                //encrypt it with server public key
                String encryptedSession = encrypt(SessionId,serverPublicKey);
                //Create a signedObject object to hold the encrypted Session Id
                SignedObject signedSession = new SignedObject(encryptedSession,clientPrivateKey,sig);
                // and send it back to server
                objectOutputStream.writeObject( signedSession );

                //Receive confirmation from server
                SignedObject signedConfirmation = (SignedObject)objectInputStream.readObject();
                boolean isConfirmationRight = signedConfirmation.verify(serverPublicKey,sig);
                String confirmation = (String)signedConfirmation.getObject();
                System.out.println("Session Id:" + SessionId);
                System.out.println("confirmation:" + decrypt(confirmation,clientPrivateKey));

                while (k != 2){
                    //generate initialize vector and send it to server
                    String initVector = generateInitVector(SessionId.length());
                    String encInitVector = encrypt(initVector,serverPublicKey);
                    objectOutputStream.writeObject(encInitVector);
                    //  Create the request
                    Scanner scanner = new Scanner(System.in);
                    System.out.println("Please Enter A new Request :");
                    System.out.println("Enter the name of the file:");
                    String name = scanner.nextLine() + ".txt";
                    System.out.println("Enter yes if you want to modify/create the file:");
                    boolean isEdited = scanner.nextLine().equals("yes");
                    String text = "";
                    if (isEdited) {
                        System.out.println("Enter the content of the file:");
                        text = scanner.nextLine();
                    }
                    Request request = new Request(name, isEdited, text);
                    //encrypt the request
                    request.siphor(initVector,SessionId);
                    SignedObject signedRequest = new SignedObject(request,clientPrivateKey, sig);
                    //send the signed object
                    objectOutputStream.writeObject(signedRequest);
                    //Receive the signed Response
                    SignedObject signedResponse = (SignedObject) objectInputStream.readObject();
                    //Verify the Response
                    boolean b = signedRequest.verify(serverPublicKey, sig);
                    Response response = (Response) signedResponse.getObject();
                    //Decrypt the response
                    response.unSiphor(initVector,SessionId);
                    System.out.println(response.getMessage());
                    if (response.getMessage().equals("file founded"))
                    {
                        System.out.println("file content ::::");
                        System.out.println(response.getText()+"\n");
                    }
                    System.out.println("enter 2 if you want to close the connection");
                    k = scanner.nextLine()=="2"?2:1;
                }
                socket.close();
            } catch (Exception e) {
                System.out.println(e);
            }
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
    private static String generateInitVector(int n)
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

        return sb.toString();
    }
    }
