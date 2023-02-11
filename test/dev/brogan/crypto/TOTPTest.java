package dev.brogan.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TOTPTest {
	private static final String[] secrets = {
		"12345678901234567890",
		"12345678901234567890123456789012",
		"1234567890123456789012345678901234567890123456789012345678901234"
	};

	HOTP.HashAlgorithm[] algorithms = {
		HOTP.HashAlgorithm.SHA1,
		HOTP.HashAlgorithm.SHA256,
		HOTP.HashAlgorithm.SHA512
	};

	long[] seconds = {
		59L,
		1111111109L,
		1111111111L,
		1234567890L,
		2000000000L,
		20000000000L
	};

	int[] totps = {
		94287082,
		46119246,
		90693936,
		7081804,
		68084774,
		25091201,
		14050471,
		67062674,
		99943326,
		89005924,
		91819424,
		93441116,
		69279037,
		90698825,
		38618901,
		65353130,
		77737706,
		47863826
	};

	@Test
	void generatesExpectedTOTPValues() {
		final int digits = 8;
		final long epoch = 0;
		final long period = 30;
		for (int i = 0; i < totps.length; i++) {
			int expectedTOTP = totps[i];
			long time = seconds[i / 3];
			HOTP.HashAlgorithm algorithm = algorithms[i % 3];
			byte[] secret = Bytes.convertTextToBytes(secrets[i % 3]);
			assertEquals(expectedTOTP, TOTP.TOTP(secret, digits, epoch, period, algorithm, time));
		}
	}
}

/*
*/