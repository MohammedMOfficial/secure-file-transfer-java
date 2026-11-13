package server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import javax.net.ssl.SSLSocket;

/** Handles one connected client (runs on a worker thread). */
public class HandleClient implements Runnable {

	public static final int MIN_PASSWORD_LENGTH = 8;
	private static final int MAX_LOGIN_ATTEMPTS = 5;
	private static final String DUMMY_SALT = "00000000000000000000000000000000";
	private static final int IDLE_TIMEOUT_MS = 10 * 60 * 1000; // drop clients that go silent

	private final SSLSocket client;
	private final String clientIp;
	private final DBHandler db = new DBHandler();
	private DataInputStream in;
	private DataOutputStream out;

	public HandleClient(SSLSocket client) {
		this.client = client;
		this.clientIp = client.getInetAddress().getHostAddress();
	}

	@Override
	public void run() {
		try {
			client.setSoTimeout(IDLE_TIMEOUT_MS);
			in = new DataInputStream(client.getInputStream());
			out = new DataOutputStream(client.getOutputStream());
			while (true) {
				String operation = in.readUTF();
				if (operation.equalsIgnoreCase("login")) {
					login();
				} else if (operation.equalsIgnoreCase("signup")) {
					signup();
				} else if (operation.equalsIgnoreCase("exit")) {
					System.out.println("Client " + clientIp + " left");
					break;
				}
			}
		} catch (IOException e) {
			System.out.println("Connection with " + clientIp + " ended: " + e.getMessage());
		} finally {
			try {
				client.close();
			} catch (IOException e) {
				// nothing more we can do
			}
		}
	}

	// ------------------------------------------------------------------ signup

	/**
	 * Protocol: client sends a username; server answers "exist", "invalid" or
	 * "not exist". On "not exist" the client sends a password and the server
	 * answers "created" or "weak". The loop repeats until an account is created.
	 */
	private void signup() throws IOException {
		while (true) {
			String username = in.readUTF();
			if (!FileSecurity.isValidUsername(username)) {
				reply("invalid");
				continue;
			}
			if (db.usernameExists(username)) {
				reply("exist");
				continue;
			}
			reply("not exist");

			String password = in.readUTF();
			if (password.length() < MIN_PASSWORD_LENGTH) {
				reply("weak");
				continue;
			}

			String salt = PasswordHasher.generateSalt();
			boolean created = db.insertUser(username, salt, PasswordHasher.hash(password, salt), "normal");
			File dir = FileSecurity.userDir(username);
			if (created && dir != null) {
				dir.mkdirs();
				db.insertLog(username, "signup");
				reply("created");
				return;
			}
			reply("exist"); // lost a race with another signup using the same name
		}
	}

	// ------------------------------------------------------------------- login

	private void login() throws IOException {
		// The block is checked against the real socket address, never an address the client claims.
		if (db.isBlocked(clientIp)) {
			System.out.println("Client " + clientIp + " is blocked");
			reply("fail");
			return;
		}
		reply("pass");

		String username = null;
		boolean logged = false;
		for (int attempt = 1; attempt <= MAX_LOGIN_ATTEMPTS; attempt++) {
			username = in.readUTF();
			String password = in.readUTF();

			String salt = db.getSalt(username);
			String stored = db.getHashedPassword(username);
			boolean ok;
			if (salt != null && stored != null) {
				ok = PasswordHasher.matches(password, salt, stored);
			} else {
				// Unknown user: still do the expensive hash so response time does not reveal valid usernames.
				PasswordHasher.hash(password, DUMMY_SALT);
				ok = false;
			}

			if (ok) {
				logged = true;
				reply("pass");
				break;
			}
			reply("fail");
			if (attempt == MAX_LOGIN_ATTEMPTS) {
				db.insertBlock(clientIp);
				System.out.println("Blocked " + clientIp + " after " + MAX_LOGIN_ATTEMPTS + " failed logins");
			}
		}

		if (logged) {
			String type = db.getUserType(username);
			String sessionKey = PasswordHasher.generateSessionKey();
			db.insertSessionKey(sessionKey, username);
			out.writeUTF(sessionKey);
			out.flush();
			db.insertLog(username, "logged in");
			try {
				loggedIn(type, sessionKey, username);
			} finally {
				db.deleteSessionKey(sessionKey, username);
			}
		}
	}

	// --------------------------------------------------------- logged-in loop

	private void loggedIn(String type, String sessionKey, String username) throws IOException {
		boolean isAdmin = "admin".equalsIgnoreCase(type);
		while (true) {
			String sk = in.readUTF();
			String operation = in.readUTF();

			if (!PasswordHasher.constantTimeEquals(sk, sessionKey)) {
				System.out.println(username + " sent an incorrect session key");
				db.insertLog(username, "wrong sessionkey");
				return;
			}

			if (operation.equalsIgnoreCase("bye")) {
				db.insertLog(username, "logged out");
				return;
			} else if (operation.equalsIgnoreCase("list")) {
				db.insertLog(username, "list");
				out.writeUTF(sessionKey);
				out.writeUTF(db.getFiles(username, isAdmin));
				out.flush();
			} else if (operation.equalsIgnoreCase("delete")) {
				handleDelete(username, isAdmin, sessionKey, type);
			} else if (operation.equalsIgnoreCase("upload")) {
				if (!handleUpload(username)) {
					return; // protocol violation: drop the connection
				}
			} else if (operation.equalsIgnoreCase("download")) {
				handleDownload(username, isAdmin, sessionKey, type);
			}
			// "nothing" and unknown operations are ignored
		}
	}

	private void handleDelete(String username, boolean isAdmin, String sessionKey, String type) throws IOException {
		out.writeUTF(sessionKey);
		out.writeUTF(type);
		out.flush();
		String requestedOwner = in.readUTF();
		String filename = in.readUTF();

		// Authorisation: only admins may touch other users' files. Normal users are
		// always restricted to their own, whatever owner name the client sent.
		String owner = isAdmin ? requestedOwner : username;
		File file = FileSecurity.resolveUserFile(owner, filename);

		if (file != null && db.fileExists(owner, filename)) {
			db.deleteFile(owner, filename);
			file.delete();
			db.insertLog(username, "deleted file: " + filename + " owned by " + owner);
			reply("success");
		} else {
			db.insertLog(username, "failed delete attempt on file: " + filename);
			reply("fail");
		}
	}

	/** @return false if the connection must be dropped */
	private boolean handleUpload(String username) throws IOException {
		String filename = in.readUTF();
		long size = in.readLong();
		if (size < 0 || size > FileSecurity.MAX_UPLOAD_BYTES) {
			reply("rejected: file too large");
			return false;
		}

		File target = FileSecurity.resolveUserFile(username, filename);
		boolean accept = target != null;
		if (accept) {
			target.getParentFile().mkdirs();
		}

		// Always consume exactly `size` bytes so the stream stays in sync, even when rejecting.
		byte[] buffer = new byte[4096];
		long remaining = size;
		try (FileOutputStream fos = accept ? new FileOutputStream(target) : null) {
			while (remaining > 0) {
				int n = in.read(buffer, 0, (int) Math.min(buffer.length, remaining));
				if (n < 0) {
					throw new IOException("client closed during upload");
				}
				if (fos != null) {
					fos.write(buffer, 0, n);
				}
				remaining -= n;
			}
		}

		if (!accept) {
			db.insertLog(username, "rejected upload with invalid file name");
			reply("rejected: invalid file name");
			return true;
		}
		db.insertFile(username, filename);
		db.insertLog(username, "upload " + filename);
		reply("ok");
		return true;
	}

	private void handleDownload(String username, boolean isAdmin, String sessionKey, String type)
			throws IOException {
		String filename = in.readUTF();
		out.writeUTF(sessionKey);
		out.writeUTF(type);
		out.flush();

		String owner = username;
		if (isAdmin) {
			owner = in.readUTF();
		}

		File file = FileSecurity.resolveUserFile(owner, filename);
		if (file == null || !db.fileExists(owner, filename) || !file.isFile()) {
			reply("not_exist");
			return;
		}

		out.writeUTF("exist");
		out.writeLong(file.length());
		try (FileInputStream fis = new FileInputStream(file)) {
			byte[] buffer = new byte[4096];
			int r;
			while ((r = fis.read(buffer)) != -1) {
				out.write(buffer, 0, r);
			}
		}
		out.flush();
		db.insertLog(username, "downloaded file: " + filename);
	}

	private void reply(String message) throws IOException {
		out.writeUTF(message);
		out.flush();
	}
}
