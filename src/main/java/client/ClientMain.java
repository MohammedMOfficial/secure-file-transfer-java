package client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Scanner;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Terminal client for the secure file-transfer server.
 *
 * Usage: ClientMain [host] [port]   (defaults: localhost 2121)
 * Trust store: set TRUSTSTORE_PATH and TRUSTSTORE_PASSWORD, or pass the
 * -Djavax.net.ssl.trustStore / -Djavax.net.ssl.trustStorePassword flags.
 */
public class ClientMain {

	private static final int MAX_LOGIN_ATTEMPTS = 5;
	private static final long MAX_UPLOAD_BYTES = 100L * 1024 * 1024; // must match the server limit

	public static void main(String[] args) {
		String trustStore = System.getenv("TRUSTSTORE_PATH");
		String trustStorePassword = System.getenv("TRUSTSTORE_PASSWORD");
		if (trustStore != null && trustStorePassword != null) {
			System.setProperty("javax.net.ssl.trustStore", trustStore);
			System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);
		}
		String host = args.length > 0 ? args[0] : "localhost";
		int port = args.length > 1 ? Integer.parseInt(args[1]) : 2121;

		Scanner kb = new Scanner(System.in);
		try (SSLSocket client = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(host,
				port)) {
			DataInputStream in = new DataInputStream(client.getInputStream());
			DataOutputStream out = new DataOutputStream(client.getOutputStream());

			while (true) {
				System.out.println("\n=========== Secure File Transfer ===========");
				System.out.println("login | signup | exit");
				System.out.print("--> ");
				String operation = kb.nextLine().trim();

				if (operation.equalsIgnoreCase("login")) {
					send(out, operation);
					login(kb, in, out);
				} else if (operation.equalsIgnoreCase("signup")) {
					send(out, operation);
					signup(kb, in, out);
				} else if (operation.equalsIgnoreCase("exit")) {
					send(out, operation);
					System.out.println("Goodbye.");
					break;
				} else {
					System.out.println("Unknown option.");
				}
			}
		} catch (IOException e) {
			System.out.println("Connection error: " + e.getMessage());
		}
	}

	private static void send(DataOutputStream out, String... parts) throws IOException {
		for (String p : parts) {
			out.writeUTF(p);
		}
		out.flush();
	}

	// ------------------------------------------------------------------ login

	private static void login(Scanner kb, DataInputStream in, DataOutputStream out) throws IOException {
		if (!in.readUTF().equalsIgnoreCase("pass")) {
			System.out.println("Too many failed attempts from this address. Please try again in 5 minutes.");
			return;
		}
		System.out.println("--------------- Login ---------------");
		for (int i = 1; i <= MAX_LOGIN_ATTEMPTS; i++) {
			System.out.print("Username: ");
			String username = kb.nextLine();
			System.out.print("Password: ");
			String password = kb.nextLine();
			send(out, username, password);

			if (in.readUTF().equalsIgnoreCase("pass")) {
				String sessionKey = in.readUTF();
				loggedIn(kb, in, out, sessionKey, username);
				return;
			}
			System.out.println("Username or password was incorrect (" + i + "/" + MAX_LOGIN_ATTEMPTS + ").");
		}
		System.out.println("Too many failed attempts. Please try again in 5 minutes.");
	}

	// ----------------------------------------------------------------- signup

	private static void signup(Scanner kb, DataInputStream in, DataOutputStream out) throws IOException {
		System.out.println("--------------- Sign up ---------------");
		System.out.println("Username: 3-50 characters (letters, digits, . _ -). Password: at least 8 characters.");
		while (true) {
			System.out.print("Username: ");
			send(out, kb.nextLine());
			String response = in.readUTF();
			if (response.equals("exist")) {
				System.out.println("That username is taken, choose another.");
				continue;
			}
			if (response.equals("invalid")) {
				System.out.println("Invalid username.");
				continue;
			}

			String password;
			while (true) {
				System.out.print("Password: ");
				password = kb.nextLine();
				System.out.print("Confirm password: ");
				if (password.equals(kb.nextLine())) {
					break;
				}
				System.out.println("Passwords do not match, try again.");
			}
			send(out, password);
			response = in.readUTF();
			if (response.equals("created")) {
				System.out.println("Account created. You can log in now.");
				return;
			}
			System.out.println(response.equals("weak") ? "Password too short (minimum 8 characters). Start again."
					: "Could not create the account, try again.");
		}
	}

	// --------------------------------------------------------------- logged in

	private static void loggedIn(Scanner kb, DataInputStream in, DataOutputStream out, String sessionKey,
			String username) throws IOException {
		System.out.println("You are logged in as " + username + ".");
		while (true) {
			System.out.println("\nlist | upload | download | delete | bye (logout)");
			System.out.print("--> ");
			String operation = kb.nextLine().trim().toLowerCase();

			switch (operation) {
			case "bye":
				send(out, sessionKey, operation);
				return;
			case "list":
				list(in, out, sessionKey);
				break;
			case "upload":
				upload(kb, in, out, sessionKey);
				break;
			case "download":
				download(kb, in, out, sessionKey);
				break;
			case "delete":
				delete(kb, in, out, sessionKey, username);
				break;
			default:
				System.out.println("Unknown option.");
			}
		}
	}

	private static void list(DataInputStream in, DataOutputStream out, String sessionKey) throws IOException {
		send(out, sessionKey, "list");
		if (!in.readUTF().equals(sessionKey)) {
			System.out.println("Unexpected response from server.");
			return;
		}
		String files = in.readUTF();
		System.out.println(files.equals("null") ? "(no files)" : files);
	}

	private static void upload(Scanner kb, DataInputStream in, DataOutputStream out, String sessionKey)
			throws IOException {
		System.out.print("Path of the file to upload: ");
		File file = new File(kb.nextLine().trim().replace("\"", ""));
		if (!file.isFile() || file.length() > MAX_UPLOAD_BYTES) {
			System.out.println("File not found, not a regular file, or larger than 100 MB.");
			send(out, sessionKey, "nothing");
			return;
		}
		send(out, sessionKey, "upload", file.getName());
		out.writeLong(file.length());
		try (FileInputStream fis = new FileInputStream(file)) {
			byte[] buffer = new byte[4096];
			int n;
			while ((n = fis.read(buffer)) != -1) {
				out.write(buffer, 0, n);
			}
		}
		out.flush();
		String result = in.readUTF();
		System.out.println(result.equals("ok") ? "Uploaded: " + file.getName() : "Upload failed (" + result + ")");
	}

	private static void download(Scanner kb, DataInputStream in, DataOutputStream out, String sessionKey)
			throws IOException {
		System.out.print("File name: ");
		String filename = kb.nextLine().trim();
		send(out, sessionKey, "download", filename);

		if (!in.readUTF().equals(sessionKey)) {
			System.out.println("Unexpected response from server.");
			return;
		}
		String type = in.readUTF();
		if (type.equalsIgnoreCase("admin")) {
			System.out.print("File owner: ");
			send(out, kb.nextLine().trim());
		}
		if (!in.readUTF().equals("exist")) {
			System.out.println("The file does not exist.");
			return;
		}

		long size = in.readLong();
		File folder = new File(System.getProperty("user.home"), "Downloads");
		folder.mkdirs();
		// Use only the last path segment so a hostile name cannot write outside Downloads.
		File target = uniqueFile(folder, new File(filename).getName());
		try (FileOutputStream fos = new FileOutputStream(target)) {
			byte[] buffer = new byte[4096];
			long remaining = size;
			while (remaining > 0) {
				int n = in.read(buffer, 0, (int) Math.min(buffer.length, remaining));
				if (n < 0) {
					throw new IOException("Connection closed during download");
				}
				fos.write(buffer, 0, n);
				remaining -= n;
			}
		}
		System.out.println("Downloaded to " + target.getAbsolutePath());
	}

	private static void delete(Scanner kb, DataInputStream in, DataOutputStream out, String sessionKey,
			String username) throws IOException {
		System.out.print("File name: ");
		String filename = kb.nextLine().trim();
		send(out, sessionKey, "delete");

		if (!in.readUTF().equals(sessionKey)) {
			System.out.println("Unexpected response from server.");
			return;
		}
		String type = in.readUTF();
		String owner = username;
		if (type.equalsIgnoreCase("admin")) {
			System.out.print("File owner: ");
			owner = kb.nextLine().trim();
		}
		send(out, owner, filename);
		System.out.println(in.readUTF().equals("success") ? "Deleted " + filename
				: "The file does not exist or you are not allowed to delete it.");
	}

	private static File uniqueFile(File folder, String name) {
		File f = new File(folder, name);
		int i = 1;
		while (f.exists()) {
			int dot = name.lastIndexOf('.');
			String base = dot > 0 ? name.substring(0, dot) : name;
			String ext = dot > 0 ? name.substring(dot) : "";
			f = new File(folder, base + " (" + i++ + ")" + ext);
		}
		return f;
	}
}
