import java.io.Serializable;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class Request implements Serializable,Cloneable {
    private String Name;
    private boolean IsEdited;
    private String Text;
    public Request(String name, boolean isEdited, String text) {
        Name = name;
        IsEdited = isEdited;
        Text = text;
    }

    public String getName() {
        return Name;
    }

    public void setName(String name) {
        Name = name;
    }

    public boolean isEdited() {
        return IsEdited;
    }

    public void setEdited(boolean edited) {
        IsEdited = edited;
    }

    public String getText() {
        return Text;
    }

    public void setText(String text) {
        Text = text;
    }


    private String key = "aesEncryptionKey";
    private String initVector = "encryptionIntVec";


    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    private String encrypt(String data) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {

        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes());
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv); // or Cipher.DECRYPT_MODE

        byte[] encrypted = cipher.doFinal(data.getBytes());

        String s = Base64.getEncoder().encodeToString(encrypted);
        return s;
    }




    private String decrypt(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {

        byte[] encrypted = Base64.getDecoder().decode(data);

        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes());
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        byte[] decrypted = cipher.doFinal(encrypted);

        String s = new String(decrypted, StandardCharsets.UTF_8);

        return s;
    }
    public void siphor(){
        try {
            this.Name = encrypt(this.Name);
            this.Text = encrypt(this.Text);
        } catch (Exception e){
            System.out.print((""));
        }
    }
    public void unSiphor(){
        try {
            this.Name = decrypt(this.Name);
            this.Text = decrypt(this.Text);
        }
        catch (Exception e) {
            System.out.print((""));
        }
    }
    @Override
    public String toString(){
        return this.Name+"\n"+this.IsEdited+"\n"+this.Text;
    }
}
