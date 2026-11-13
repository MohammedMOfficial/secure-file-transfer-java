package server;

import java.io.File;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

/**
 * TLS file-transfer server.
 *
 * Configuration (environment variables):
 *   KEYSTORE_PATH, KEYSTORE_PASSWORD  - server certificate (or pass -Djavax.net.ssl.keyStore=...)
 *   PORT                              - listening port (default 2121)
 *   MAX_CLIENTS                       - size of the worker thread pool (default 50)
 */
public class ServerMain {

	public static void main(String[] args) {
		String keyStore = System.getenv("KEYSTORE_PATH");
		String keyStorePassword = System.getenv("KEYSTORE_PASSWORD");
		if (keyStore != null && keyStorePassword != null) {
			System.setProperty("javax.net.ssl.keyStore", keyStore);
			System.setProperty("javax.net.ssl.keyStorePassword", keyStorePassword);
		}
		if (System.getProperty("javax.net.ssl.keyStore") == null) {
			System.out.println("No keystore configured. Set KEYSTORE_PATH and KEYSTORE_PASSWORD (see README).");
			return;
		}

		int port = Integer.parseInt(envOr("PORT", "2121"));
		int maxClients = Integer.parseInt(envOr("MAX_CLIENTS", "50"));
		new File(FileSecurity.BASE_DIR).mkdirs();

		// A bounded pool: a flood of connections cannot create unlimited threads.
		ExecutorService pool = Executors.newFixedThreadPool(maxClients);

		try (SSLServerSocket server = (SSLServerSocket) SSLServerSocketFactory.getDefault().createServerSocket(port)) {
			System.out.println("Server listening (TLS) on port " + port);
			while (true) {
				try {
					SSLSocket socket = (SSLSocket) server.accept();
					System.out.println("New client " + socket.getInetAddress().getHostAddress() + " connected...");
					pool.execute(new HandleClient(socket));
				} catch (IOException e) {
					System.out.println("client exception: " + e.getMessage());
				}
			}
		} catch (IOException e) {
			System.out.println("server exception: " + e.getMessage());
		} finally {
			pool.shutdown();
		}
	}

	private static String envOr(String name, String fallback) {
		String v = System.getenv(name);
		return (v == null || v.isEmpty()) ? fallback : v;
	}
}
