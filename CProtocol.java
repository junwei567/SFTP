import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/*
Client's Protocol
Obtain server's public key from server's certificate using X509Certificate class
- cert verification
- check (signed) cert validity
- extract public key from signed cert
*/

public class CProtocol {

    private static InputStream CA;
    private static CertificateFactory cf;
    private static X509Certificate ServerCert;
    private static X509Certificate CACert;
    private static PublicKey CAKey;
    private static PublicKey serverKey;

    public CProtocol (String CA) throws IOException {
        try {
            this.CA = new FileInputStream(CA);
            cf = CertificateFactory.getInstance("X.509");
            ServerCert = (X509Certificate)cf.generateCertificate(this.CA);
            CAKey = ServerCert.getPublicKey();
        } catch (CertificateException e) {
            System.out.println(e);
        }
        this.CA.close();
    }

    public void getCertificate (InputStream cert) throws CertificateException {

    }

    public void verifyCert() {

    }

    public void getPublicKey() {
        
    }

}
