package dev.brogan.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HOTPTest {
	private static final String secretASCII = "12345678901234567890";
	private static final byte[] secret = secretASCII.getBytes();
	private static final byte[] zero = new byte[8];

	private static final String[] intermediateHMACValues = {
		"cc93cf18508d94934c64b65d8ba7667fb7cde4b0",
		"75a48a19d4cbe100644e8ac1397eea747a2d33ab",
		"0bacb7fa082fef30782211938bc1c5e70416ff44",
		"66c28227d03a2d5529262ff016a1e6ef76557ece",
		"a904c900a64b35909874b33e61c5938a8e15ed1c",
		"a37e783d7b7233c083d4f62926c7a25f238d0316",
		"bc9cd28561042c83f219324d3c607256c03272ae",
		"a4fb960c0bc06e1eabb804e5b397cdc4b45596fa",
		"1b3c89f65e6c9e883012052823443f048b4332db",
		"1637409809a679dc698207310c8c7fc07290d9e5"
	};

	private static final int[] truncatedValues = {
		0x4c93cf18,
		0x41397eea,
		0x82fef30,
		0x66ef7655,
		0x61c5938a,
		0x33c083d4,
		0x7256c032,
		0x4e5b397,
		0x2823443f,
		0x2679dc69
	};

	private static final int[] HOTPValues = {
		755224,
		287082,
		359152,
		969429,
		338314,
		254676,
		287922,
		162583,
		399871,
		520489
	};

	private static final String HEX = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	private static final String HEX_CHARS = "0123456789abcdef";

	@Test
	void generatesCorrectHOTPValues() {
		for (int i = 0; i < HOTPValues.length; i++) {
			byte[] counter = HOTP.convertLongToBytes(i);
			int hotp = HOTP.HOTP(secret, counter);
			assertEquals(HOTPValues[i], hotp);
		}
	}

	@Test
	void generatesCorrectIntermediateHMACValues() {
		for (int i = 0; i < intermediateHMACValues.length; i++) {
			byte[] counter = HOTP.convertLongToBytes(i);
			byte[] hmac = HOTP.HMAC_SHA1(secret, counter);
			assertEquals(intermediateHMACValues[i], HOTP.convertBytesToHex(hmac));
		}
	}

	@Test
	void generates8DigitHOTP() {
		int i = 7;
		byte[] counter = HOTP.convertLongToBytes(i);
		int digits = 8;
		assertEquals(truncatedValues[i], HOTP.HOTP(secret, counter, digits));
	}

	@Test
	void failsWithShortDigits() {
		int digits = 5;
		assertThrows(Throwable.class, () -> HOTP.HOTP(secret, zero, digits));
	}

	@Test
	void failsWithLongDigits() {
		int digits = 10;
		assertThrows(Throwable.class, () -> HOTP.HOTP(secret, zero, digits));
	}

	@Test
	void failsWithShortSecret() {
		byte[] secret = "hello".getBytes();
		byte[] counter = new byte[8];
		assertThrows(Throwable.class, () -> HOTP.HOTP(secret, counter));
	}

	@Test
	void truncates() {
		int digits = 6;
		for (int i = 0; i < HOTPValues.length; i++) {
			assertEquals(HOTPValues[i], HOTP.Truncate(HOTP.convertHexToBytes(intermediateHMACValues[i]), digits));
		}
	}

	@Test
	void dynamicallyTruncates() {
		for (int i = 0; i < truncatedValues.length; i++) {
			assertEquals(truncatedValues[i], HOTP.DT(HOTP.convertHexToBytes(intermediateHMACValues[i])));
		}
	}

	@Test
	void convertsHexToBytes() {
		byte[] bytes = {1, 35, 69, 103, -119, -85, -51, -17};
		assertArrayEquals(bytes, HOTP.convertHexToBytes(HEX_CHARS));
		assertArrayEquals(bytes, HOTP.convertHexToBytes(HEX_CHARS.toUpperCase()));
	}

	@Test
	void convertsHexCharToByte() {
		char[] chars = HEX_CHARS.toCharArray();
		for (int i = 0; i < chars.length; i++) {
			assertEquals(i, HOTP.hexCharToByte(chars[i]));
		}

		chars = HEX_CHARS.toUpperCase().toCharArray();
		for (int i = 0; i < chars.length; i++) {
			assertEquals(i, HOTP.hexCharToByte(chars[i]));
		}
	}

	@Test
	void convertsBytesToHex() {
		byte[] bytes = {0x00, 0x47, 0x3f, 0x1a};
		String hex = "00473f1a";
		assertEquals(hex, HOTP.convertBytesToHex(bytes));
	}

	@Test
	void zeroPads() {
		assertEquals("2345", HOTP.zeroPad("2345", 2));
		assertEquals("002345", HOTP.zeroPad("2345", 6));
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
		assertArrayEquals(b, HOTP.convertLongToBytes(l));
	}
}
