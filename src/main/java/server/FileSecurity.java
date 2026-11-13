package server;

import java.io.File;
import java.io.IOException;
import java.util.regex.Pattern;

/** Input validation for anything the client sends that ends up in a file path. */
public final class FileSecurity {

	public static final String BASE_DIR = "server_files";
	public static final long MAX_UPLOAD_BYTES = 100L * 1024 * 1024; // 100 MB

	private static final Pattern USERNAME = Pattern.compile("^[A-Za-z0-9_.-]{3,50}$");

	private FileSecurity() {
	}

	public static boolean isValidUsername(String username) {
		return username != null && USERNAME.matcher(username).matches() && !username.contains("..");
	}

	/** A file name only: no directories, no traversal, no control characters. */
	public static boolean isValidFilename(String filename) {
		if (filename == null || filename.isEmpty() || filename.length() > 200) {
			return false;
		}
		if (filename.equals(".") || filename.equals("..")) {
			return false;
		}
		for (char c : filename.toCharArray()) {
			if (c < 32 || c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<'
					|| c == '>' || c == '|') {
				return false;
			}
		}
		return true;
	}

	/**
	 * Resolves BASE_DIR/username/filename and verifies the result really is inside
	 * BASE_DIR/username (defence in depth on top of the validation above).
	 *
	 * @return the file, or null if the names are invalid or escape the user folder
	 */
	public static File resolveUserFile(String username, String filename) {
		if (!isValidUsername(username) || !isValidFilename(filename)) {
			return null;
		}
		try {
			File userDir = new File(BASE_DIR, username).getCanonicalFile();
			File target = new File(userDir, filename).getCanonicalFile();
			if (!target.getParentFile().equals(userDir)) {
				return null;
			}
			return target;
		} catch (IOException e) {
			return null;
		}
	}

	public static File userDir(String username) {
		if (!isValidUsername(username)) {
			return null;
		}
		return new File(BASE_DIR, username);
	}
}
