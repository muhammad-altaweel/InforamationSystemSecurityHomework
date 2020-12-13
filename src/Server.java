import java.net.ServerSocket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Server {

    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair pair = keyPairGenerator.generateKeyPair();
        PrivateKey serverPrivateKey = pair.getPrivate();
        PublicKey serverPublicKey = pair.getPublic();
        try (ServerSocket listener = new ServerSocket(11111)) {
            System.out.println("The Main server is running...");
            ExecutorService pool = Executors.newFixedThreadPool(20);
            while (true)
            {
                pool.execute(new OneServer(listener.accept(),serverPublicKey,serverPrivateKey));
            }
        }
    }
}
