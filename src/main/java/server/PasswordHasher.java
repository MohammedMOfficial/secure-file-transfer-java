package server;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Password hashing and random token generation.
 *
 * Passwords are hashed with PBKDF2-HMAC-SHA256 (a deliberately slow, standard
 * key-derivation function) using a per-user random salt.
 */
public final class PasswordHasher {

	private static final SecureRandom RANDOM = new SecureRandom();
	private static final int ITERATIONS = 210_000; // OWASP recommendation for PBKDF2-HMAC-SHA256
	private static final int KEY_BITS = 256;

	private PasswordHasher() {
	}

	/** 16 random bytes, hex encoded (32 characters). */
	public static String generateSalt() {
		return randomHex(16);
	}

	/** 32 random bytes, hex encoded (64 characters). Used for session keys. */
	public static String generateSessionKey() {
		return randomHex(32);
	}

	public static String hash(String password, String salt) {
		try {
			KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(java.nio.charset.StandardCharsets.UTF_8),
					ITERATIONS, KEY_BITS);
			byte[] hash = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
			return toHex(hash);
		} catch (Exception e) {
			throw new IllegalStateException("Could not hash password", e);
		}
	}

	/** Constant-time comparison so response time does not leak how much matched. */
	public static boolean matches(String password, String salt, String expectedHash) {
		if (password == null || salt == null || expectedHash == null) {
			return false;
		}
		byte[] actual = hash(password, salt).getBytes(java.nio.charset.StandardCharsets.UTF_8);
		byte[] expected = expectedHash.getBytes(java.nio.charset.StandardCharsets.UTF_8);
		return MessageDigest.isEqual(actual, expected);
	}

	public static boolean constantTimeEquals(String a, String b) {
		if (a == null || b == null) {
			return false;
		}
		return MessageDigest.isEqual(a.getBytes(java.nio.charset.StandardCharsets.UTF_8),
				b.getBytes(java.nio.charset.StandardCharsets.UTF_8));
	}

	private static String randomHex(int bytes) {
		byte[] buf = new byte[bytes];
		RANDOM.nextBytes(buf);
		return toHex(buf);
	}

	private static String toHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder(bytes.length * 2);
		for (byte b : bytes) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}
}
