import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ServerCP1 {

	private static byte[] nonce = new byte[32];
    // private static byte[] encryptedNonce = new byte[128];

	public static void main(String[] args) {

    	int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

			while (!connectionSocket.isClosed()) {

				// * start of Authentication Protocol

				// InputStream fis = new FileInputStream("cacsertificate.crt");
				InputStream fis = new FileInputStream("certificate_1004379.crt");
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				X509Certificate serverCert =(X509Certificate) cf.generateCertificate(fis);
				byte[] serverCertEncoded = serverCert.getEncoded();
				// PublicKey key = serverCert.getPublicKey();

				//private key
				PrivateKey privateKey = PrivateKeyReader();
				// get nonce from client
				System.out.println("Get nonce from client");
				fromClient.read(nonce);
				// encrypt nonce for client
				System.out.println("Encrypt nonce for client");
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.ENCRYPT_MODE, privateKey);
				byte[] encryptedNonce = cipher.doFinal(nonce);
				// send nonce to client
				System.out.println("Sent encrypted nonce to clint");
				toClient.write(encryptedNonce);
				// ! is it necessary?
				toClient.flush();

				// * send cert to client
				System.out.println("Sent encoded cert to client");
				toClient.write(serverCertEncoded);
				toClient.flush();

				// * Authentication Protocol done after client verifies

				int packetType = fromClient.readInt();

				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					byte [] filename = new byte[numBytes];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filename, 0, numBytes);

					fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {

					int numBytes = fromClient.readInt();
					byte [] block = new byte[numBytes];
					fromClient.readFully(block, 0, numBytes);

					if (numBytes > 0)
						bufferedFileOutputStream.write(block, 0, numBytes);

					if (numBytes < 117) {
						System.out.println("Closing connection...");

						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
						fromClient.close();
						toClient.close();
						connectionSocket.close();
					}
				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}

	public static PrivateKey PrivateKeyReader() throws Exception{

		byte[] keyBytes = Files.readAllBytes(Paths.get("private_key.der"));

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

}
