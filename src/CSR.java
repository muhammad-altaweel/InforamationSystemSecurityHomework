import java.io.Serializable;
import java.security.PublicKey;

public class CSR implements Serializable {
    private String Name;
    private PublicKey publicKey;

    public CSR(String name, PublicKey publicKey) {
        this.Name = name;
        this.publicKey = publicKey;
    }

    public String getName() {
        return Name;
    }

    public void setName(String name) {
        Name = name;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }
}
