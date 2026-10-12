// Java crypto usage (web parity fixture).
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import javax.crypto.Cipher;

class Legacy {
    void run() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        Cipher desede = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        KeyPairGenerator mldsa = KeyPairGenerator.getInstance("ML-DSA");
    }
}
