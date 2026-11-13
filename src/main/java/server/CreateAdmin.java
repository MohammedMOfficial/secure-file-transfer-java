package server;

/**
 * One-off helper to create an admin account (admins cannot sign up through the client).
 *
 * Usage: CreateAdmin <username> <password>
 */
public class CreateAdmin {
	public static void main(String[] args) {
		if (args.length != 2) {
			System.out.println("Usage: CreateAdmin <username> <password>");
			return;
		}
		String username = args[0];
		String password = args[1];
		if (!FileSecurity.isValidUsername(username) || password.length() < HandleClient.MIN_PASSWORD_LENGTH) {
			System.out.println("Username must be 3-50 chars (letters, digits, . _ -) and password at least "
					+ HandleClient.MIN_PASSWORD_LENGTH + " characters.");
			return;
		}
		DBHandler db = new DBHandler();
		String salt = PasswordHasher.generateSalt();
		boolean ok = db.insertUser(username, salt, PasswordHasher.hash(password, salt), "admin");
		System.out.println(ok ? "Admin '" + username + "' created." : "Could not create admin (does the user already exist?).");
	}
}
