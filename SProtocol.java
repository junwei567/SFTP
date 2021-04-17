import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class SProtocol {
    
    private static InputStream CA;
    private static CertificateFactory cf;
    private static X509Certificate ServerCert;
    private static X509Certificate CACert;
    private static PublicKey CAKey;
    private static PublicKey serverKey;

    public SProtocol (String CA) throws IOException {
        try {
            this.CA = new FileInputStream(CA);
            cf = CertificateFactory.getInstance("X.509");
            ServerCert = (X509Certificate)cf.generateCertificate(this.CA);
            CAKey = ServerCert.getPublicKey();

        } catch (CertificateException e) {
            System.out.println(e);
        }
    }

}
