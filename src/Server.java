import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Server {

    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair pair = keyPairGenerator.generateKeyPair();
        PrivateKey serverPrivateKey = pair.getPrivate();
        PublicKey serverPublicKey = pair.getPublic();
        PublicKey CaPublicKey;
        X509Certificate serverCertificate;
        String serverName = "Main-Server";
        //1.Connect with CA to Get serverCertificate 2.Generate Csr and send it to CA 3.Receive Certificate from CA
        try {
            Socket socket = new Socket("localhost", 22222);
            OutputStream outputStream = socket.getOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
            InputStream inputStream = socket.getInputStream();
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
            //Receive CA public key
            CaPublicKey = (PublicKey) objectInputStream.readObject();
            //send CSR to CA
            CSR serverCsr = new CSR(serverName, serverPublicKey);
            objectOutputStream.writeObject(serverCsr);
            String filepath = (String) objectInputStream.readObject();
            String secretMessage = "";
            //read the secret Message
            File file = new File(filepath);
            BufferedReader br = new BufferedReader(new FileReader(file));
            String st;
            while ((st = br.readLine()) != null)
                secretMessage += st;
            br.close();
            //sign the secret Message and send it to CA
            Signature sig = Signature.getInstance("SHA256withRSA");
            SignedObject signedSecretMessage = new SignedObject(secretMessage, serverPrivateKey, sig);
            objectOutputStream.writeObject(signedSecretMessage);
            //Receive the serverCertificate from CA
            serverCertificate = (X509Certificate) objectInputStream.readObject();
            if (Verify(serverCertificate, CaPublicKey)) {
                System.out.println("Certificate Received and Verified successfully");
            } else {
                System.out.println("Certificate was not received or did not verified successfully");
            }
            socket.close();
            //System.out.println(serverCertificate);
        } catch (Exception e) {
            System.out.println("Could not connect with Certificate Authority");
            return;
        }
        try (ServerSocket listener = new ServerSocket(11111)) {
            System.out.println("The Main server is running...");
            ExecutorService pool = Executors.newFixedThreadPool(20);
            while (true) {
                pool.execute(new OneServer(listener.accept(), serverPublicKey, serverPrivateKey, serverCertificate, CaPublicKey));
            }
        }
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
