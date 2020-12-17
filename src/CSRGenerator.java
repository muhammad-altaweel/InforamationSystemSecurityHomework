import sun.security.pkcs10.PKCS10;
import sun.security.x509.X500Name;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.*;

public class CSRGenerator {
    public static void main(String[] args) {
        CSRGenerator csrGeneration = new CSRGenerator();

        // Generate key pair
        KeyPair keyPair = csrGeneration.generateKeyPair("RSA", 1024);
        System.out.println("KeyPair generated");

        byte[] csrData = csrGeneration.generateCSR("SHA256WithRSA", keyPair);

        System.out.println(new String(csrData));
    }

    /**
     * Generate the desired CSR for signing
     *
     * @param sigAlg
     * @param keyPair
     * @return
     */
    byte[] generateCSR(String sigAlg, KeyPair keyPair) {
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(outStream);

        try {
            X500Name x500Name = new X500Name("CN=google.com");

            Signature sig = Signature.getInstance(sigAlg);

            sig.initSign(keyPair.getPrivate());

            PKCS10 pkcs10 = new PKCS10(keyPair.getPublic());
//          pkcs10.encodeAndSign(new X500Signer(sig, x500Name));   // For Java 6
            pkcs10.encodeAndSign(x500Name, sig);                   // For Java 7 and Java 8
            pkcs10.print(printStream);
            byte[] csrBytes = outStream.toByteArray();
            return csrBytes;
        } catch (Exception ex)
        {
            ex.printStackTrace();
        } finally
        {
            if(null != outStream) {
                try {
                    outStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            if(null != printStream) {
                printStream.close();
            }
        }

        return new byte[0];
    }

    /**
     * Generate the desired keypair
     *
     * @param alg
     * @param keySize
     * @return
     */
    KeyPair generateKeyPair(String alg, int keySize) {
        try{
            KeyPairGenerator keyPairGenerator = null;
            keyPairGenerator = KeyPairGenerator.getInstance(alg);

            keyPairGenerator.initialize(keySize);

            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
}