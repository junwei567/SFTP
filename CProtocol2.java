import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public abstract class CProtocol2 {

	private static byte[] nonce = new byte[32];
    private static byte[] encryptedNonce = new byte[128];

	public static void main(String[] args) {

    	String filename;// = "100.txt";
    	// if (args.length > 0) filename = args[0];

    	String serverAddress = "localhost";
    	// if (args.length > 1) filename = args[1];

    	int port = 4321;
    	// if (args.length > 2) port = Integer.parseInt(args[2]);

		int numBytes = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;
		BufferedOutputStream bufferedOutputStream = null;

		long timeStarted = System.nanoTime();

		try {
			PublicKey publickey = PublicKeyReader();
			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			// * Start of Authentication Protocol
			// InputStream fis = new FileInputStream("certificate_1004379.crt");
			InputStream fis = new FileInputStream("cacsertificate.crt");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate CAcert =(X509Certificate) cf.generateCertificate(fis);
			PublicKey key = CAcert.getPublicKey();

			toServer.writeInt(42); // start AP with server

			// * Generate nonce
			System.out.println("Generate nonce");
			SecureRandom random = new SecureRandom();
			random.nextBytes(nonce);
			System.out.println("Sent nonce to server");
			toServer.write(nonce);

			// * Get encrypted nonce from server
			System.out.println("Get encrypted nonce from server");
			fromServer.read(encryptedNonce);
			// * Get cert from the nonce

			System.out.println("Get encoded cert from server");
			X509Certificate ServerCert = (X509Certificate) cf.generateCertificate(fromServer);
			
			// * verify cert
			// use my own public key to verify encoded cert
			System.out.println("Verifying cert from server");
			ServerCert.checkValidity();
			ServerCert.verify(key);
			// * cert should be verified at this point

			// * verify server
			// get server's public key from server cert
			// use server's public key to decrypt the nonce is indeed generated by me
			PublicKey serverKey = ServerCert.getPublicKey();
			Cipher decipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			decipher.init(Cipher.DECRYPT_MODE, serverKey);
			byte[] decryptNonce = decipher.doFinal(encryptedNonce);

			if (Arrays.equals(nonce, decryptNonce)) {
				// server is correct
				System.out.println("Server is verified");
			} else {
				// its an ambush!
				toServer.writeInt(43); // ! close conn same as packettype 4???
				System.out.println("Server verification failed");
				System.out.println("Closing all connections...");
				toServer.close();
				fromServer.close();
				clientSocket.close();
			}
			// * Authentication Protocol done

			// * CP2 generate session key
			SecretKey sessionKey = KeyGenerator.getInstance("AES").generateKey();
			Cipher sessionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			sessionCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
			byte[] encodedSessionKey = sessionKey.getEncoded();

			Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCipher.init(Cipher.ENCRYPT_MODE, publickey);
			byte[] encryptSessionKey = rsaCipher.doFinal(encodedSessionKey);

			System.out.println("Send session key to server");
			bufferedOutputStream = new BufferedOutputStream(toServer);

			toServer.write(53);
			toServer.writeInt(encryptSessionKey.length);

			bufferedOutputStream.write(encryptSessionKey, 0, encryptSessionKey.length);
			bufferedOutputStream.flush();
			System.out.println("Session key sent...");
			// ! paused here. Left server implementation and file d/encryption 

			// Key AESKey = new SecretKeySpec("secret".getBytes(), "AES"); 

			// * for loop for multiple file transfer
			for (int i = 0; i < args.length; i ++) {

				filename = args[i];

				// System.out.println("Sending file...");
				System.out.println("Sending " + filename);

				// Send the filename
				toServer.writeInt(0);
				toServer.writeInt(filename.getBytes().length);
				toServer.write(filename.getBytes());
				toServer.flush();

				// Open the file
				fileInputStream = new FileInputStream(filename);
				bufferedFileInputStream = new BufferedInputStream(fileInputStream);

				byte [] fromFileBuffer = new byte[117];

				// Send the file
				for (boolean fileEnded = false; !fileEnded;) {
					// number of bytes to be transferred (inside the buffer)
					numBytes = bufferedFileInputStream.read(fromFileBuffer);
					fileEnded = numBytes < 117;

					toServer.writeInt(1);
					toServer.writeInt(numBytes);

					// * CP2: use session key
				

					// * CP1: encrypts file data before sending RSA
					Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					cipher.init(Cipher.ENCRYPT_MODE, publickey);
					byte[] encryptFromFileBuffer = cipher.doFinal(fromFileBuffer);
					int encryptNumBytes = encryptFromFileBuffer.length;
					toServer.writeInt(encryptNumBytes);

					toServer.write(encryptFromFileBuffer);
					toServer.flush();
			
				}

				System.out.println("Finished sending " + filename);

				if (i == args.length -1) {
					// * End of File
					toServer.writeInt(4);
					bufferedFileInputStream.close();
					fileInputStream.close();
				}
			}
			System.out.println("Closing connection...");

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}

	public static byte [] encrypt() {
		return new byte [32];
	}

	public static PublicKey PublicKeyReader() throws Exception{

		byte[] keyBytes = Files.readAllBytes(Paths.get("public_key.der"));

		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);

	}
}
