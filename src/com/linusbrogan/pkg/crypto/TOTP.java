package com.linusbrogan.pkg.crypto;

/** An implementation of [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) */
public class TOTP {
	private static final int DEFAULT_DIGITS = 6;
	// Default system parameters (page 4)
	private static final long DEFAULT_START_TIME = 0;
	private static final long DEFAULT_TIME_STEP = 30;

	/**
	 * Generates a TOTP value.
	 * @param K shared secret
	 */
	public static int TOTP(byte[] K) {
		return TOTP(K, DEFAULT_DIGITS, DEFAULT_START_TIME, DEFAULT_TIME_STEP, HOTP.HashAlgorithm.SHA1);
	}

	/**
	 * Generates a TOTP value.
	 * @param K shared secret
	 * @param Digit TOTP length
	 * @param T0 "the Unix time to start counting time steps" (page 4)
	 * @param X "the time step in seconds" (page 4)
	 * @param algorithm HMAC algorithm
	 */
	public static int TOTP(byte[] K, int Digit, long T0, long X, HOTP.HashAlgorithm algorithm) {
		return TOTP(K, Digit, T0, X, algorithm, now());
	}

	/**
	 * Generates a TOTP value.
	 * @param K shared secret
	 * @param Digit TOTP length
	 * @param T0 "the Unix time to start counting time steps" (page 4)
	 * @param X "the time step in seconds" (page 4)
	 * @param algorithm HMAC algorithm
	 * @param now Current Unix time for the TOTP
	 */
	static int TOTP(byte[] K, int Digit, long T0, long X, HOTP.HashAlgorithm algorithm, long now) {
		long timeSteps = (now - T0) / X;
		byte[] T = Bytes.convertLongToBytes(timeSteps);
		return HOTP.HOTP(K, T, Digit, algorithm);
	}

	/**
	 * @return current Unix time in seconds
	 */
	private static long now() {
		return System.currentTimeMillis() / 1000L;
	}
}
