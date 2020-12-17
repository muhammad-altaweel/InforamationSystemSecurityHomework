import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignedObject;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedList;

public class OneServer implements Runnable {
    Socket socket;
    PublicKey serverPublicKey;
    PrivateKey serverPrivateKey;
    X509Certificate serverCertificate;
    PublicKey CaPublicKey;
    HashMap< String, LinkedList<String> > Authorities;
    static final String path = ".\\Sources";


    public OneServer(Socket socket, PublicKey serverPublicKey, PrivateKey serverPrivateKey, X509Certificate serverCertificate, PublicKey caPublicKey) {
        this.socket = socket;
        this.serverPublicKey = serverPublicKey;
        this.serverPrivateKey = serverPrivateKey;
        this.serverCertificate = serverCertificate;
        this.CaPublicKey = caPublicKey;
    }

    @Override
    public void run(){
            try {
                String message = "";
                String to_return;
                to_return = "";
                String SessionId;
                String clientName;
                String serverName = serverCertificate.getIssuerDN().getName().substring(3);
                Authorities = getAuthorities();
                Signature sig = Signature.getInstance("SHA256withRSA");
                X509Certificate clientCertificate;
                InputStream inputStream = socket.getInputStream();
                ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
                OutputStream outputStream = socket.getOutputStream();
                ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
                // Receive certificate  from client
                clientCertificate = (X509Certificate) objectInputStream.readObject();
                PublicKey clientPublicKey = clientCertificate.getPublicKey();
                //Send certificate to client
                objectOutputStream.writeObject(serverCertificate);
                //Receive ClientName from client
                clientName = (String) objectInputStream.readObject();
                //Send ServerName to client
                objectOutputStream.writeObject(serverName);
                //verify client certificate
                if(Verify(clientCertificate,CaPublicKey) && clientName.equals(clientCertificate.getIssuerDN().getName().substring(3))) {
                    System.out.println("Client Certificate Was Verified");
                    //Receive session ID from client
                    SignedObject signedSession = (SignedObject) objectInputStream.readObject();
                    SessionId = (String) signedSession.getObject();
                    //Decrypt it with private
                    SessionId = decrypt(SessionId, serverPrivateKey);
                    //Send confirmation to client
                    String res = encrypt("ok", clientPublicKey);
                    //pack it with signedObject
                    SignedObject signedConfirmation = new SignedObject(res, serverPrivateKey, sig);
                    objectOutputStream.writeObject(signedConfirmation);
                    //Recieve Requests from client
                    while (true) {
                        to_return = "";
                        message = "";
                        //Receive initVector from client:
                        String initVector = (String) objectInputStream.readObject();
                        initVector = decrypt(initVector, serverPrivateKey);
                        //Receive the signedRequest from client
                        SignedObject signedRequest = (SignedObject) objectInputStream.readObject();
                        // Verify the signed Request
                        boolean b = signedRequest.verify(clientPublicKey, sig);
                        Request request = (Request) signedRequest.getObject();
                        //decrypt the encrypted Request
                        request.unSiphor(initVector, SessionId);
                        String name = request.getName();
                        boolean isEdited = request.isEdited();
                        String text = request.getText();
                        if (isEdited) { //need to modify the file
                            try {
                                if(!find_file(name))
                                {
                                    addToMap(Authorities,clientName,name);
                                    FileWriter fileWriter = new FileWriter(path + "\\" + name);
                                    PrintWriter printWriter = new PrintWriter(fileWriter);
                                    printWriter.print(text);
                                    printWriter.close();
                                    message = "file edited successfully";
                                    to_return = text;
                                    printWriter.close();
                                }
                                else if(hasAuthrorization(Authorities,clientName,name)) {

                                    FileWriter fileWriter = new FileWriter(path + "\\" + name);
                                    PrintWriter printWriter = new PrintWriter(fileWriter);
                                    printWriter.print(text);
                                    printWriter.close();
                                    message = "file edited successfully";
                                    to_return = text;
                                    printWriter.close();
                                }
                                else
                                {
                                    message = "You Are not Authorized to modify this file";
                                }

                            } catch (Exception e) {
                                System.out.println(e);
                            }
                        }
                        else { // read the file text and return it to
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
                        //create the Response
                        Response response = new Response(to_return, message);
                        //encrypt the Response
                        response.siphor(initVector, SessionId);
                        //sign the Response
                        SignedObject signedResponse = new SignedObject(response, serverPrivateKey, sig);
                        //send the signed Response to client
                        objectOutputStream.writeObject(signedResponse);
                    }
                }
            } catch (Exception e) {
                try {
                    //close the connection
                    socket.close();
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
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
    //check if the certificate is correct compatible with a certain public key
    public boolean Verify(X509Certificate certificate,PublicKey publicKey) {
        try {
            certificate.verify(publicKey);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    public boolean find_file(String name) {
        File f = new File(path);
        String names[] = f.list();
        for (String k : names)
        {
            if (k.equals(name))
                return true;
        }
        return false;
    }
    public void  addToMap(HashMap<String, LinkedList<String>> map, String userId, String newDocument){
        if(map.containsKey(userId))
            map.get(userId).add(newDocument);
        else
        {
            LinkedList<String> linkedList = new LinkedList<String>();
            linkedList.add(newDocument);
            map.put(userId,linkedList);
        }
    }
    public boolean hasAuthrorization(HashMap< String, LinkedList<String> >map,String userId,String documentName){
        if(map.containsKey(userId))
            for(String k : map.get(userId)){
                if(k.equals(documentName))
                    return true;
            }
        return false;
    }
    public HashMap< String, LinkedList<String> > getAuthorities(){
        HashMap< String, LinkedList<String> > map =new HashMap< String, LinkedList<String> >() ;
        String client = "client01";
        LinkedList<String> linkedList = new LinkedList<String>();
        linkedList.add("hani.txt");
        linkedList.add("hasan.txt");
        linkedList.add("maher.txt");
        linkedList.add("mady.txt");
        map.put(client,linkedList);
        return map;
    }
}
