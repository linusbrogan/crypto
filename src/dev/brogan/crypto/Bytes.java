package dev.brogan.crypto;

public class Bytes {
	private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

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
