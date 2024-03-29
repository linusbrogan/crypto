package com.linusbrogan.pkg.crypto;

public class Bytes {
	private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

	/**
	 * @return the bytes of l in big-endian order
	 */
	public static byte[] convertLongToBytes(long l) {
		final int bytesPerLong = 8;
		final int bitsPerByte = 8;
		byte[] bytes = new byte[bytesPerLong];
		for (int i = 0; i < bytesPerLong; i++) {
			bytes[bytesPerLong - 1 - i] = (byte) (l >> (i * bitsPerByte));
		}
		return bytes;
	}

	/** Left-pads string with zeroes to at least targetLength. */
	public static String zeroPad(String string, int targetLength) {
		int zeroes = targetLength - string.length();
		if (targetLength < string.length()) zeroes = 0;
		return "0".repeat(zeroes) + string;
	}

	/**
	 * @param hex an even-length string of hexadecimal digits
	 */
	public static byte[] convertHexToBytes(String hex) {
		int length = hex.length();
		assert length % 2 != 1;
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
	public static byte hexCharToByte(char c) {
		if (c >= '0' && c <= '9') return (byte) (c - '0');
		if (c >= 'a' && c <= 'f') return (byte) (c - 'a' + 10);
		if (c >= 'A' && c <= 'F') return (byte) (c - 'A' + 10);

		// A hexadecimal digit would have been handled already, so fail.
		assert false;
		return 0;
	}

	public static String convertBytesToHex(byte[] bytes) {
		StringBuilder nybbles = new StringBuilder();
		for (byte b : bytes) {
			int high = (byte) (b >>> 4) & 0xf;
			int low = b & 0xf;

			nybbles.append(HEX_CHARS[high]);
			nybbles.append(HEX_CHARS[low]);
		}
		return nybbles.toString();
	}

	public static byte[] xor(byte[] a, byte[] b) {
		assert a.length == b.length;
		byte[] xor = new byte[a.length];
		for (int i = 0; i < xor.length; i++) {
			xor[i] = (byte) (a[i] ^ b[i]);
		}
		return xor;
	}

	public static byte[][] transpose(byte[][] matrix) {
		byte[][] transpose = new byte[matrix[0].length][matrix.length];
		for (int r = 0; r < matrix.length; r++) {
			for (int c = 0; c < matrix[0].length; c++) {
				transpose[c][r] = matrix[r][c];
			}
		}
		return transpose;
	}

	/**
	 * @param text ASCII string
	 */
	public static byte[] convertTextToBytes(String text) {
		int length = text.length();
		byte[] bytes = new byte[length];
		for (int i = 0; i < length; i++) {
			bytes[i] = (byte) text.charAt(i);
		}
		return bytes;
	}
}
