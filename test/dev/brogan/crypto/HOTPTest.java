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

	@Test
	void generatesCorrectHOTPValues() {
		for (int i = 0; i < HOTPValues.length; i++) {
			byte[] counter = Bytes.convertLongToBytes(i);
			int hotp = HOTP.HOTP(secret, counter);
			assertEquals(HOTPValues[i], hotp);
		}
	}

	@Test
	void generatesCorrectIntermediateHMACValues() {
		for (int i = 0; i < intermediateHMACValues.length; i++) {
			byte[] counter = Bytes.convertLongToBytes(i);
			byte[] hmac = HOTP.HMAC_SHA1(secret, counter);
			assertEquals(intermediateHMACValues[i], Bytes.convertBytesToHex(hmac));
		}
	}

	@Test
	void generates8DigitHOTP() {
		int i = 7;
		byte[] counter = Bytes.convertLongToBytes(i);
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
			assertEquals(HOTPValues[i], HOTP.Truncate(Bytes.convertHexToBytes(intermediateHMACValues[i]), digits));
		}
	}

	@Test
	void dynamicallyTruncates() {
		for (int i = 0; i < truncatedValues.length; i++) {
			assertEquals(truncatedValues[i], HOTP.DT(Bytes.convertHexToBytes(intermediateHMACValues[i])));
		}
	}
}
