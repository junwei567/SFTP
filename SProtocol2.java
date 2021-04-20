import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.nio.file.Files;
import java.nio.file.Paths;

public class SProtocol2 {

	private static byte[] nonce = new byte[32];
	private static byte[] encryptSessionKey;

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
			//private key
			PrivateKey privateKey = PrivateKeyReader();
			SecretKey sessionkey;
			Cipher sessionKeyCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

			while (!connectionSocket.isClosed()) {
				int packetType = fromClient.readInt();

				if (packetType == 2) {
					System.out.println("Starting Authentication Protocol with client");
					// * start of Authentication Protocol
					// InputStream fis = new FileInputStream("cacsertificate.crt");
					InputStream fis = new FileInputStream("certificate_1004379.crt");
					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					X509Certificate serverCert =(X509Certificate) cf.generateCertificate(fis);
					byte[] serverCertEncoded = serverCert.getEncoded();
					// PublicKey key = serverCert.getPublicKey();

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
					toClient.flush();

					// * send cert to client
					System.out.println("Sent encoded cert to client");
					toClient.write(serverCertEncoded);
					toClient.flush();

					// * Authentication Protocol done after client verifies
				}

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
					int encryptNumBytes = fromClient.readInt();
					byte [] block = new byte[encryptNumBytes];
					fromClient.readFully(block, 0, encryptNumBytes);
					//? 2. decrypte file chunks using session key
					byte[] decryptBlock = sessionKeyCipher.doFinal(block);
				

					if (numBytes > 0)
						bufferedFileOutputStream.write(decryptBlock, 0, numBytes);

					if (numBytes < 117) {
						System.out.println("File Received");

						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
				
					}
				}
				if (packetType == 4) {
					System.out.println("close conn");
					fromClient.close();
					toClient.close();
					connectionSocket.close();
				}
				if (packetType == 3) {
					System.out.println("Receiving session key from client");
					int encryptSessionKeySize = fromClient.readInt();
					encryptSessionKey = new byte[encryptSessionKeySize];
					//
					fromClient.readFully(encryptSessionKey, 0, encryptSessionKeySize);

					System.out.println("Session Key received");
					Cipher decipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					decipher.init(Cipher.DECRYPT_MODE, privateKey);
					//? 1. decrypt symmetric (session) key with private key
					byte[] decryptSessionKeyByte = decipher.doFinal(encryptSessionKey);
					sessionkey = new SecretKeySpec(decryptSessionKeyByte, 0, decryptSessionKeyByte.length, "AES");
					sessionKeyCipher.init(Cipher.DECRYPT_MODE, sessionkey);
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