package com.linusbrogan.pkg.crypto;

import java.util.Arrays;

/**
 * Implements AES-CTR, with prepended IV.
 */
public class AES_CTR {
	private static final int BYTE_MASK = 0xff;

	private final AES aes;

	public AES_CTR(AES aes) {
		this.aes = aes;
	}

	/**
	 * @param key AES key of length of 16, 24, or 32 bytes
	 */
	public AES_CTR(byte[] key) {
		this(new AES(key));
	}

	/**
	 * @param iv 16 byte initialization vector
	 * @param message data to encrypt
	 * @return ciphertext prepended with the initialization vector
	 */
	public byte[] encrypt(byte[] iv, byte[] message) {
		assert iv.length == AES.BLOCK_SIZE;

		// Prepend IV.
		byte[] ciphertext = new byte[iv.length + message.length];
		int cursor = 0;
		System.arraycopy(iv, 0, ciphertext, cursor, iv.length);
		cursor += iv.length;

		// Encrypt full blocks.
		for (int i = 0; i < message.length / AES.BLOCK_SIZE; i++) {
			byte[] m_i = Arrays.copyOfRange(message, i * AES.BLOCK_SIZE, (i + 1) * AES.BLOCK_SIZE);
			byte[] c_i = Bytes.xor(m_i, aes.encrypt(iv));
			System.arraycopy(c_i, 0, ciphertext, cursor, c_i.length);
			cursor += c_i.length;
			iv = incrementBlock(iv);
		}

		// Encrypt the final block.
		int remainder = message.length % AES.BLOCK_SIZE;
		byte[] m_f = new byte[AES.BLOCK_SIZE];
		System.arraycopy(message, message.length - remainder, m_f, 0, remainder);
		byte[] c_f = Bytes.xor(m_f, aes.encrypt(iv));
		System.arraycopy(c_f, 0, ciphertext, cursor, remainder);

		return ciphertext;
	}

	/**
	 * @param ciphertext ciphertext prepended with the initialization vector
	 * @return plaintext message
	 */
	public byte[] decrypt(byte[] ciphertext) {
		assert ciphertext.length >= AES.BLOCK_SIZE;

		// Extract IV.
		byte[] iv = Arrays.copyOfRange(ciphertext, 0, AES.BLOCK_SIZE);
		int cCursor = AES.BLOCK_SIZE;

		// Decrypt message.
		byte[] message = new byte[ciphertext.length - iv.length];
		int mCursor = 0;
		while (cCursor < ciphertext.length) {
			byte[] c_i = Arrays.copyOfRange(ciphertext, cCursor, Math.min(cCursor + AES.BLOCK_SIZE, ciphertext.length));
			cCursor += AES.BLOCK_SIZE;
			byte[] m_i = Bytes.xor(c_i, Arrays.copyOfRange(aes.encrypt(iv), 0, c_i.length));
			System.arraycopy(m_i, 0, message, mCursor, m_i.length);
			mCursor += m_i.length;
			iv = incrementBlock(iv);
		}

		return message;
	}

	static byte[] incrementBlock(byte[] block) {
		assert block.length == AES.BLOCK_SIZE;
		byte[] next = Arrays.copyOf(block, block.length);
		int i = next.length - 1;
		next[i] += 1;
		while (next[i] == 0 && i > 0) {
			i--;
			next[i] += 1;
		}

		return next;
	}
}
