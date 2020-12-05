import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class OneServer implements Runnable {
    Socket socket;
    PublicKey serverPublicKey;
    PrivateKey serverPrivateKey;
    static final String path = ".\\Sources";
    public boolean find_file(String name) {
        File f = new File(path);
        String names[] = f.list();
        for (String k : names) {
            if (k.equals(name))
                return true;
        }
        return false;
    }

    public OneServer(Socket socket, PublicKey serverPublicKey, PrivateKey serverPrivateKey) {
        this.socket = socket;
        this.serverPublicKey = serverPublicKey;
        this.serverPrivateKey = serverPrivateKey;
    }

    @Override
    public void run(){
            try {
                String message = "";
                String to_return;
                to_return = "";
                String SessionId;
                // Recive public from client
                InputStream inputStream = socket.getInputStream();
                ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
                PublicKey clientPublicKey = (PublicKey) objectInputStream.readObject();
                //send public to client
                OutputStream outputStream = socket.getOutputStream();
                ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
                objectOutputStream.writeObject(serverPublicKey);
                //Recieve session ID from client
                SessionId = (String) objectInputStream.readObject();
                //Decrypt it with private
                SessionId = decrypt(SessionId, serverPrivateKey);
                //send confirmation to client
                String res = encrypt("ok", clientPublicKey);
                objectOutputStream.writeObject(res);
                //Recieve Requests from client
                while(true) {
                    to_return="";
                    message = "";
                    Request request = (Request) objectInputStream.readObject();
                    request.setKey(SessionId);
                    request.unSiphor();
                    String name = request.getName();
                    boolean isEdited = request.isEdited();
                    String text = request.getText();
                    if (isEdited) { //need to modify the file
                        try {
                            FileWriter fileWriter = new FileWriter(path + "\\" + name);
                            PrintWriter printWriter = new PrintWriter(fileWriter);
                            printWriter.print(text);
                            printWriter.close();
                            message = "file edited successfully";
                            to_return = text;
                            printWriter.close();
                        } catch (Exception e) {
                            System.out.println(e.getCause());
                        }
                    } else { // read the file text and return it to
                        if (find_file(name)) {
                            File file = new File(path + "\\" + name);
                            BufferedReader br = new BufferedReader(new FileReader(file));
                            String st;
                            while ((st = br.readLine()) != null)
                                to_return += st;
                            message = "file founded";
                            br.close();
                        } else {
                            message = "file does not existed";
                        }
                    }
                    Response response = new Response(to_return, message);
                    response.setKey(SessionId);
                    response.siphor();
                    //ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
                    objectOutputStream.writeObject(response);
                }
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