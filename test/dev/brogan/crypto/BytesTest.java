package dev.brogan.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class BytesTest {
	private static final String HEX_CHARS = "0123456789abcdef";

	@Test
	void convertsHexToBytes() {
		byte[] bytes = {1, 35, 69, 103, -119, -85, -51, -17};
		assertArrayEquals(bytes, Bytes.convertHexToBytes(HEX_CHARS));
		assertArrayEquals(bytes, Bytes.convertHexToBytes(HEX_CHARS.toUpperCase()));
	}

	@Test
	void failsConvertingHalfBytesToHex() {
		assertThrows(AssertionError.class, () -> Bytes.convertHexToBytes("abc"));
	}

	@Test
	void convertsHexCharToByte() {
		char[] chars = HEX_CHARS.toCharArray();
		for (int i = 0; i < chars.length; i++) {
			assertEquals(i, Bytes.hexCharToByte(chars[i]));
		}

		chars = HEX_CHARS.toUpperCase().toCharArray();
		for (int i = 0; i < chars.length; i++) {
			assertEquals(i, Bytes.hexCharToByte(chars[i]));
		}
	}

	@Test
	void convertsBytesToHex() {
		byte[] bytes = {0x00, 0x47, 0x3f, 0x1a};
		String hex = "00473f1a";
		assertEquals(hex, Bytes.convertBytesToHex(bytes));
	}

	@Test
	void zeroPads() {
		assertEquals("2345", Bytes.zeroPad("2345", 2));
		assertEquals("002345", Bytes.zeroPad("2345", 6));
	}

	@Test
	void convertsLongToBytes() {
		long l = 0x1234567890abcdefL;
		byte[] b = {
			0x12,
			0x34,
			0x56,
			0x78,
			(byte) 0x90,
			(byte) 0xab,
			(byte) 0xcd,
			(byte) 0xef
		};
		assertArrayEquals(b, Bytes.convertLongToBytes(l));
	}
}
