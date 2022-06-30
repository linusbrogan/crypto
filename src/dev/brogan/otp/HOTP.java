package dev.brogan.otp;

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
	private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();


	/**
	 * Generates a 6-digit HOTP value.
	 * @param K "shared secret between client and server" (page 5).
	 * @param C "8-byte counter value, the moving factor" (page 5).
	 */
	public static int HOTP(String K, long C) {
		return HOTP(K, C, DEFAULT_DIGITS);
	}

	/**
	 * Generates an HOTP value.
	 * @param K "shared secret between client and server" (page 5).
	 * @param C "8-byte counter value, the moving factor" (page 5).
	 * @param Digit "number of digits in an HOTP value" (page 6).
	 */
	public static int HOTP(String K, long C, int Digit) {
		// Check length requirements.
		assert Digit >= MINIMUM_DIGITS;
		assert Digit <= MAXIMUM_DIGITS;
		assert K.getBytes().length >= MINIMUM_SECRET_BYTES;

		return Truncate(HMAC_SHA1(K, C), Digit);
	}

	/**
	 * @param K The HMAC key
	 * @param C The 8-byte HMAC data
	 */
	static byte[] HMAC_SHA1(String K, long C) {
		final String algorithm = "HmacSHA1";
		try {
			Key key = new SecretKeySpec(K.getBytes(), algorithm);
			Mac mac = Mac.getInstance(algorithm);
			mac.init(key);
			byte[] input = convertLongToBytes(C);
			return mac.doFinal(input);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * @return the bytes of l in big-endian order
	 */
	static byte[] convertLongToBytes(long l) {
		final int bytesPerLong = 8;
		final int bitsPerByte = 8;
		byte[] bytes = new byte[bytesPerLong];
		for (int i = 0; i < bytesPerLong; i++) {
			bytes[bytesPerLong - 1 - i] = (byte) (l >> (i * bitsPerByte));
		}
		return bytes;
	}

	/** Left-pads string with zeroes to at least targetLength. */
	static String zeroPad(String string, int targetLength) {
		int zeroes = targetLength - string.length();
		if (targetLength < string.length()) zeroes = 0;
		return "0".repeat(zeroes) + string;
	}

	/**
	 * "Converts an HMAC-SHA-1 value into an HOTP value" (page 6).
	 * @param hmac
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

	/**
	 * @param hex an even-length string of hexadecimal digits
	 */
	static byte[] convertHexToBytes(String hex) {
		int length = hex.length();
		assert length % 1 != 1;
		byte[] bytes = new byte[length / 2];
		for (int i = 0; i < length; i += 2) {
			char high = hex.charAt(i);
			char low = hex.charAt(i + 1);
			bytes[i / 2] = (byte) ((hexCharToByte(high) << 4) + hexCharToByte(low));
		}
		return bytes;
	}

	/**
	 * @param c a hexadecimal digit
	 */
	static byte hexCharToByte(char c) {
		if (c >= '0' && c <= '9') return (byte) (c - '0');
		if (c >= 'a' && c <= 'f') return (byte) (c - 'a' + 10);
		if (c >= 'A' && c <= 'F') return (byte) (c - 'A' + 10);

		// A hexadecimal digit would have been handled already, so fail.
		assert false;
		return 0;
	}

	static String convertBytesToHex(byte[] bytes) {
		StringBuilder nybbles = new StringBuilder();
		for (byte b : bytes) {
			int high = (byte) (b >>> 4) & 0xf;
			int low = b & 0xf;

			nybbles.append(HEX_CHARS[high]);
			nybbles.append(HEX_CHARS[low]);
		}
		return nybbles.toString();
	}
}
