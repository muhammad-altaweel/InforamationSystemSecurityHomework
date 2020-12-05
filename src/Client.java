import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;

public class Client {
    public static void main(String args[]) throws Exception {
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
                //recieve public key from server
                PublicKey serverPublicKey = (PublicKey)objectInputStream.readObject();
                //generate session Id
                SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
                String SessionId = Base64.getEncoder().encodeToString(secretKey.getEncoded());
                //encrypt it with server public key and send it back to server
                objectOutputStream.writeObject(encrypt(SessionId,serverPublicKey));
                //Recieve confirmation from server
                String confirmation = (String)objectInputStream.readObject();
                System.out.println("Session Id:"+SessionId);
                System.out.println("confimation:"+decrypt(confirmation,clientPrivateKey));
                while (k != 2){
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
                    request.setKey(SessionId);
                    //encrypt the request
                    request.siphor();
                    //send the request
                    objectOutputStream.writeObject(request);
                    //Recieve the response
                    Response response = (Response) objectInputStream.readObject();
                    response.setKey(SessionId);
                    //Decrypt the response
                    response.unSiphor();
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
                System.out.println(e.getCause());
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
            System.out.println(e.getCause());
        }
        return "";
    }
    }
