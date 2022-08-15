package dev.brogan.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/** An implementation of [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) */
public class HOTP {
	// "Implementations MUST extract a 6-digit code at a minimum" (page 7).
	private static final int DEFAULT_DIGITS = 6;
	private static final int MINIMUM_DIGITS = 6;
	// Truncating to 31 bits yields at most floor(31 * ln(10) / ln(2)) = 9 digits.
	private static final int MAXIMUM_DIGITS = 9;
	// "The length of the shared secret MUST be at least 128 bits" (page 5).
	private static final int MINIMUM_SECRET_BYTES = 128 / 8;

	/**
	 * Generates a 6-digit HOTP value.
	 * @param K "shared secret between client and server" (page 5).
	 * @param C "8-byte counter value, the moving factor" (page 5).
	 */
	public static int HOTP(byte[] K, byte[] C) {
		return HOTP(K, C, DEFAULT_DIGITS);
	}

	/**
	 * Generates an HOTP value.
	 * @param K "shared secret between client and server" (page 5).
	 * @param C "8-byte counter value, the moving factor" (page 5).
	 * @param Digit "number of digits in an HOTP value" (page 6).
	 */
	public static int HOTP(byte[] K, byte[] C, int Digit) {
		// Check length requirements.
		assert Digit >= MINIMUM_DIGITS;
		assert Digit <= MAXIMUM_DIGITS;
		assert K.length >= MINIMUM_SECRET_BYTES;

		return Truncate(HMAC_SHA1(K, C), Digit);
	}

	/**
	 * @param K The HMAC key
	 * @param C The HMAC data
	 */
	static byte[] HMAC_SHA1(byte[] K, byte[] C) {
		final String algorithm = "HmacSHA1";
		try {
			Key key = new SecretKeySpec(K, algorithm);
			Mac mac = Mac.getInstance(algorithm);
			mac.init(key);
			byte[] input = C;
			return mac.doFinal(input);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * "Converts an HMAC-SHA-1 value into an HOTP value" (page 6).
	 * @param Digit "number of digits in an HOTP value" (page 6).
	 */
	static int Truncate(byte[] hmac, int Digit) {
		final int Snum = DT(hmac);
		final int D = Snum % (int) Math.pow(10, Digit);
		return D;
	}

	/**
	 * Dynamic Truncation
	 * Extracts 31 bits of the HMAC.
	 * @param string a 20-byte HMAC
	 */
	static int DT(byte[] string) {
		byte Offset = (byte) (string[19] & 0xf);
		byte[] P = Arrays.copyOfRange(string, Offset, Offset + 4);
		int dynamicBinaryCode = (P[0] & 0x7f) << 24 | (P[1] & 0xff) << 16 | (P[2] & 0xff) << 8 | (P[3] & 0xff);
		return dynamicBinaryCode;
	}
}
