package dev.brogan.crypto;

import java.util.Arrays;

/**
 * Implements AES-CBC, with padding and prepended IV.
 */
public class AES_CBC {
	private static final int BYTE_MASK = 0xff;

	private final AES aes;

	public AES_CBC(AES aes) {
		this.aes = aes;
	}

	/**
	 * @param key AES key of length of 16, 24, or 32 bytes
	 */
	public AES_CBC(byte[] key) {
		this(new AES(key));
	}

	/**
	 * @param iv 16 byte initialization vector
	 * @param message data to encrypt
	 * @return padded ciphertext prepended with the initialization vector
	 */
	public byte[] encrypt(byte[] iv, byte[] message) {
		assert iv.length == AES.BLOCK_SIZE;

		// Pad up to a full block.
		int paddedMessageLength = ((message.length / AES.BLOCK_SIZE) + 1) * AES.BLOCK_SIZE;

		// Prepend IV.
		byte[] ciphertext = new byte[iv.length + paddedMessageLength];
		int cursor = 0;
		System.arraycopy(iv, 0, ciphertext, cursor, iv.length);
		cursor += iv.length;

		// Encrypt full blocks.
		for (int i = 0; i < message.length / AES.BLOCK_SIZE; i++) {
			byte[] m_i = Arrays.copyOfRange(message, i * AES.BLOCK_SIZE, (i + 1) * AES.BLOCK_SIZE);
			byte[] c_i = aes.encrypt(Bytes.xor(m_i, iv));
			System.arraycopy(c_i, 0, ciphertext, cursor, c_i.length);
			cursor += c_i.length;
			iv = c_i;
		}

		// Pad the final block.
		int remainder = message.length % AES.BLOCK_SIZE;
		byte pad = (byte) (AES.BLOCK_SIZE - remainder);
		byte[] m_f = new byte[AES.BLOCK_SIZE];
		for (int i = 0; i < AES.BLOCK_SIZE; i++) {
			m_f[i] = i < remainder ? message[message.length - remainder + i] : pad;
		}
		byte[] c_f = aes.encrypt(Bytes.xor(m_f, iv));
		System.arraycopy(c_f, 0, ciphertext, cursor, c_f.length);

		return ciphertext;
	}

	/**
	 * @param ciphertext padded ciphertext prepended with the initialization vector
	 * @return plaintext message
	 */
	public byte[] decrypt(byte[] ciphertext) {
		assert ciphertext.length % AES.BLOCK_SIZE == 0;
		assert ciphertext.length > AES.BLOCK_SIZE;

		// Extract IV.
		byte[] iv = Arrays.copyOfRange(ciphertext, 0, AES.BLOCK_SIZE);
		int cCursor = AES.BLOCK_SIZE;

		// Decrypt padded message.
		int paddedMessageLength = (ciphertext.length / AES.BLOCK_SIZE - 1) * AES.BLOCK_SIZE;
		byte[] paddedMessage = new byte[paddedMessageLength];
		int mCursor = 0;
		while (cCursor < ciphertext.length) {
			byte[] c_i = Arrays.copyOfRange(ciphertext, cCursor, cCursor + AES.BLOCK_SIZE);
			cCursor += AES.BLOCK_SIZE;
			byte[] m_i = Bytes.xor(iv, aes.decrypt(c_i));
			System.arraycopy(m_i, 0, paddedMessage, mCursor, m_i.length);
			mCursor += m_i.length;
			iv = c_i;
		}

		// Remove the pad.
		int pad = paddedMessage[paddedMessage.length - 1] & BYTE_MASK;
		assert pad <= AES.BLOCK_SIZE;
		return Arrays.copyOfRange(paddedMessage, 0, paddedMessageLength - pad);
	}
}
