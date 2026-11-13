package server;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * All database access for the server.
 *
 * Every query uses a PreparedStatement with bound parameters, so user input is
 * never concatenated into SQL (this prevents SQL injection). Each call opens and
 * closes its own connection with try-with-resources, so calls from different
 * client threads never share state.
 *
 * Configuration comes from environment variables so no secrets live in the code:
 * DB_URL, DB_USER, DB_PASSWORD.
 */
public class DBHandler {

	private static final String DB_URL = env("DB_URL",
			"jdbc:mysql://localhost:3306/zt_ftp?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC");
	private static final String DB_USER = env("DB_USER", "root");
	private static final String DB_PASSWORD = env("DB_PASSWORD", "");

	/** How long an IP stays blocked after too many failed logins. */
	public static final int BLOCK_MINUTES = 5;

	private static String env(String name, String fallback) {
		String value = System.getenv(name);
		return (value == null || value.isEmpty()) ? fallback : value;
	}

	private Connection open() throws SQLException {
		return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
	}

	// ---------------------------------------------------------------- blocking

	/** True if the IP is currently blocked. Expired blocks are removed first. */
	public boolean isBlocked(String ip) {
		try (Connection c = open()) {
			try (PreparedStatement ps = c
					.prepareStatement("DELETE FROM Block WHERE time < (NOW() - INTERVAL " + BLOCK_MINUTES + " MINUTE)")) {
				ps.executeUpdate();
			}
			try (PreparedStatement ps = c.prepareStatement("SELECT 1 FROM Block WHERE ipaddress = ?")) {
				ps.setString(1, ip);
				try (ResultSet rs = ps.executeQuery()) {
					return rs.next();
				}
			}
		} catch (SQLException e) {
			System.out.println("isBlocked error: " + e.getMessage());
			return true; // fail closed: if we cannot check, do not allow login attempts
		}
	}

	public void insertBlock(String ip) {
		String sql = "INSERT INTO Block (ipaddress, time) VALUES (?, NOW()) ON DUPLICATE KEY UPDATE time = NOW()";
		try (Connection c = open(); PreparedStatement ps = c.prepareStatement(sql)) {
			ps.setString(1, ip);
			ps.executeUpdate();
		} catch (SQLException e) {
			System.out.println("insertBlock error: " + e.getMessage());
		}
	}

	// ------------------------------------------------------------------- users

	public boolean usernameExists(String username) {
		return getString("SELECT username FROM Userinfo WHERE username = ?", username) != null;
	}

	public String getUserType(String username) {
		return getString("SELECT usertype FROM Userinfo WHERE username = ?", username);
	}

	public String getSalt(String username) {
		return getString("SELECT salt FROM Userinfo WHERE username = ?", username);
	}

	public String getHashedPassword(String username) {
		return getString("SELECT hashedpassword FROM Userinfo WHERE username = ?", username);
	}

	/** @return true if the user was created, false if the name was taken or on error */
	public boolean insertUser(String username, String salt, String hashedPassword, String userType) {
		String sql = "INSERT INTO Userinfo (username, salt, hashedpassword, usertype) VALUES (?, ?, ?, ?)";
		try (Connection c = open(); PreparedStatement ps = c.prepareStatement(sql)) {
			ps.setString(1, username);
			ps.setString(2, salt);
			ps.setString(3, hashedPassword);
			ps.setString(4, userType);
			return ps.executeUpdate() == 1;
		} catch (SQLException e) {
			System.out.println("insertUser error: " + e.getMessage());
			return false;
		}
	}

	// ---------------------------------------------------------------- sessions

	public void insertSessionKey(String sessionKey, String username) {
		update("INSERT INTO Sessionkey (sessionkey, username) VALUES (?, ?)", sessionKey, username);
	}

	public boolean checkSessionKey(String sessionKey, String username) {
		return getString("SELECT sessionkey FROM Sessionkey WHERE sessionkey = ? AND username = ?", sessionKey,
				username) != null;
	}

	public void deleteSessionKey(String sessionKey, String username) {
		update("DELETE FROM Sessionkey WHERE sessionkey = ? AND username = ?", sessionKey, username);
	}

	// ------------------------------------------------------------------- files

	/** Records a file. Uploading the same name again just replaces the file on disk. */
	public void insertFile(String username, String filename) {
		update("INSERT IGNORE INTO File (username, filename) VALUES (?, ?)", username, filename);
	}

	public void deleteFile(String owner, String filename) {
		update("DELETE FROM File WHERE username = ? AND filename = ?", owner, filename);
	}

	public boolean fileExists(String owner, String filename) {
		return getString("SELECT filename FROM File WHERE username = ? AND filename = ?", owner, filename) != null;
	}

	/**
	 * Lists files, one per line. Admins see every file as "owner/filename";
	 * normal users see only their own. Returns "null" when there is nothing to list
	 * (kept from the original wire protocol).
	 */
	public String getFiles(String username, boolean isAdmin) {
		StringBuilder files = new StringBuilder();
		String sql = isAdmin ? "SELECT username, filename FROM File ORDER BY username, filename"
				: "SELECT username, filename FROM File WHERE username = ? ORDER BY filename";
		try (Connection c = open(); PreparedStatement ps = c.prepareStatement(sql)) {
			if (!isAdmin) {
				ps.setString(1, username);
			}
			try (ResultSet rs = ps.executeQuery()) {
				while (rs.next()) {
					if (files.length() > 0) {
						files.append('\n');
					}
					if (isAdmin) {
						files.append(rs.getString("username")).append('/');
					}
					files.append(rs.getString("filename"));
				}
			}
		} catch (SQLException e) {
			System.out.println("getFiles error: " + e.getMessage());
		}
		return files.length() == 0 ? "null" : files.toString();
	}

	// -------------------------------------------------------------------- logs

	public void insertLog(String username, String operation) {
		update("INSERT INTO Log (username, operation, time) VALUES (?, ?, NOW())", username, operation);
	}

	// ----------------------------------------------------------------- helpers

	private String getString(String sql, String... params) {
		try (Connection c = open(); PreparedStatement ps = c.prepareStatement(sql)) {
			for (int i = 0; i < params.length; i++) {
				ps.setString(i + 1, params[i]);
			}
			try (ResultSet rs = ps.executeQuery()) {
				return rs.next() ? rs.getString(1) : null;
			}
		} catch (SQLException e) {
			System.out.println("query error: " + e.getMessage());
			return null;
		}
	}

	private void update(String sql, String... params) {
		try (Connection c = open(); PreparedStatement ps = c.prepareStatement(sql)) {
			for (int i = 0; i < params.length; i++) {
				ps.setString(i + 1, params[i]);
			}
			ps.executeUpdate();
		} catch (SQLException e) {
			System.out.println("update error: " + e.getMessage());
		}
	}
}
