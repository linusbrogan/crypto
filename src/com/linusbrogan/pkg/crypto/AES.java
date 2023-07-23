package com.linusbrogan.pkg.crypto;

import java.util.Arrays;

/** An implementation of [FIPS 197](https://doi.org/10.6028/NIST.FIPS.197) */
public class AES {
	public static final int BLOCK_SIZE = 16;

	private static final int BYTE_MASK = 0xff;
	/** Word: "A group of 32 bits that is treated either as a single entity or as an array of 4 bytes" (page 6). */
	private static final int WORD_SIZE = 4;
	/** "Number of columns (32-bit words) comprising the State" (page 7). */
	private static final int Nb = 4;
	/**
	 * "Non-linear substitution table used in several byte substitution transformations and in the Key Expansion routine to perform a one-for-one substitution of a byte value" (page 6).
	 * Specified in Sec. 5.1.1.
	 */
	private static final byte[] S_BOX = Bytes.convertHexToBytes("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16");
	/** Inverse S-box (page 22). */
	private static final byte[] INV_S_BOX = Bytes.convertHexToBytes("52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd12572f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d8490d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af41fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cefa0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d");

	/**
	 * "The round constant word array" (page 7).
	 * Specified in Sec. 5.2.
	 */
	// AES accesses Rcon[i] for i < max(Nb * (Nr + 1) / Nk) = 11 (maximum for AES-128), so Rcon must have length 11 (Fig. 11).
	private static final byte[][] Rcon = new byte[11][WORD_SIZE];
	{
		byte x = 1;
		for (int i = 1; i < Rcon.length; i++) {
			Rcon[i][0] = x;
			x = xtime(x);
		}
	}

	/** "Number of 32-bit words comprising the Cipher Key" (page 7). */
	private final int Nk;
	/** "Number of rounds, which is a function of Nk and Nb (which is fixed)" (page 7). */
	private final int Nr;
	/** Key schedule (Sec 5.2) */
	private final byte[][] w;

	public AES(byte[] key) {
		AESMode mode = selectModeForKey(key.length);
		this.Nk = mode.Nk;
		this.Nr = mode.Nr;
		w = KeyExpansion(key);
	}

	static AESMode selectModeForKey(int keyLength) {
		for (AESMode mode : AESMode.values()) {
			if (keyLength == mode.keyLength) {
				return mode;
			}
		}
		return null;
	}

	/** Multiplication in GF(2^8) (Sec. 4.2). */
	static byte mult(byte a, byte b) {
		byte product = 0;
		byte leftTerm = a;
		for (int i = 0; i < 8; i++) {
			byte bit = (byte) (b & 1);
			product ^= bit * leftTerm;
			leftTerm = xtime(leftTerm);
			b >>= 1;
		}
		return product;
	}

	/** Multiplication by x = {02} in GF(2^8) (Sec. 4.2.1). */
	static byte xtime(byte a) {
		boolean isHighBitSet = a < 0;
		a <<= 1;
		if (isHighBitSet) {
			a ^= 0x1b;
		}
		return a;
	}

	/**
	 * Cipher: "Series of transformations that converts plaintext to ciphertext using the Cipher Key" (page 6).
	 * Specified in Sec. 5.1.
	 * @param in message block to encrypt
	 * @return ciphertext block
	 */
	public byte[] encrypt(byte[] in) {
		assert in.length == WORD_SIZE * Nb;
		assert w.length == Nb * (Nr + 1);
		byte[][] state = new byte[WORD_SIZE][Nb];
		for (int r = 0; r < WORD_SIZE; r++) {
			for (int c = 0; c < Nb; c++) {
				state[r][c] = in[r + WORD_SIZE * c];
			}
		}
		AddRoundKey(state, Arrays.copyOfRange(w, 0, Nb - 1 + 1));
		for (int round = 1; round <= Nr - 1; round++) {
			SubBytes(state);
			ShiftRows(state);
			MixColumns(state);
			AddRoundKey(state, Arrays.copyOfRange(w, round * Nb, (round + 1) * Nb - 1 + 1));
		}
		SubBytes(state);
		ShiftRows(state);
		AddRoundKey(state, Arrays.copyOfRange(w, Nr * Nb, (Nr + 1) * Nb - 1 + 1));

		byte[] out = new byte[in.length];
		for (int r = 0; r < WORD_SIZE; r++) {
			for (int c = 0; c < Nb; c++) {
				out[r + WORD_SIZE * c] = state[r][c];
			}
		}
		return out;
	}

	/**
	 * "Transformation in the Cipher that processes the State using a nonlinear byte substitution table (S-box) that operates on each of the State bytes independently" (page 7).
	 * Specified in Sec. 5.1.1.
	 * */
	static void SubBytes(byte[][] state) {
		for (int r = 0; r < WORD_SIZE; r++) {
			for (int c = 0; c < Nb; c++) {
				state[r][c] = S_BOX[state[r][c] & BYTE_MASK];
			}
		}
	}

	/**
	 * "Transformation in the Cipher that processes the State by cyclically shifting the last three rows of the State by different offsets" (page 7).
	 * Specified in Sec. 5.1.2.
	 */
	static void ShiftRows(byte[][] state) {
		for (int r = 1; r < state.length; r++) {
			byte[] newRow = new byte[state[r].length];
			for (int c = 0; c < Nb; c++) {
				newRow[c] = state[r][(c + r) % Nb];
			}
			state[r] = newRow;
		}
	}

	/**
	 * "Transformation in the Cipher that takes all of the columns of the State and mixes their data (independently of one another) to produce new columns" (page 7).
	 * Specified in Sec. 5.1.3.
	 */
	static void MixColumns(byte[][] state) {
		for (int c = 0; c < Nb; c++) {
			byte[] newColumn = new byte[WORD_SIZE];
			newColumn[0] = (byte) (mult((byte) 2, state[0][c]) ^ mult((byte) 3, state[1][c]) ^ state[2][c] ^ state[3][c]);
			newColumn[1] = (byte) (state[0][c] ^ mult((byte) 2, state[1][c]) ^ mult((byte) 3, state[2][c]) ^ state[3][c]);
			newColumn[2] = (byte) (state[0][c] ^ state[1][c] ^ mult((byte) 2, state[2][c]) ^ mult((byte) 3, state[3][c]));
			newColumn[3] = (byte) (mult((byte) 3, state[0][c]) ^ state[1][c] ^ state[2][c] ^ mult((byte) 2, state[3][c]));
			for (int r = 0; r < newColumn.length; r++) {
				state[r][c] = newColumn[r];
			}
		}
	}

	/**
	 * "Transformation in the Cipher and Inverse Cipher in which a Round Key is added to the State using an XOR operation" (page 6).
	 * Specified in Sec. 5.1.4.
	 */
	static void AddRoundKey(byte[][] state, byte[][] w) {
		for (int c = 0; c < Nb; c++) {
			for (int r = 0; r < WORD_SIZE; r++) {
				state[r][c] ^= w[c][r];
			}
		}
	}

	/**
	 * "Function used in the Key Expansion routine that takes a four-byte input word and applies an S-box to each of the four bytes to produce an output word" (page 7).
	 * Specified in Sec. 5.2.
	 */
	static byte[] SubWord(byte[] word) {
		byte[] subWord = new byte[word.length];
		for (int i = 0 ; i < word.length; i++) {
			subWord[i] = S_BOX[word[i] & BYTE_MASK];
		}
		return subWord;
	}

	/**
	 * "Function used in the Key Expansion routine that takes a four-byte word and performs a cyclic permutation" (page 7).
	 * Specified in Sec. 5.2.
	 */
	static byte[] RotWord(byte[] word) {
		byte[] rotWord = new byte[word.length];
		for (int i = 0; i < word.length; i++) {
			rotWord[i] = word[(i + 1) % word.length];
		}
		return rotWord;
	}

	/**
	 * "Routine used to generate a series of Round Keys from the Cipher Key" (page 6).
	 * Specified in Sec. 5.2.
	 */
	byte[][] KeyExpansion(byte[] key) {
		assert key.length == WORD_SIZE * Nk;

		byte[][] w = new byte[Nb * (Nr + 1)][WORD_SIZE];

		for (int i = 0; i < Nk; i++) {
			for (int j = 0; j < w[i].length; j++) {
				w[i][j] = key[4 * i + j];
			}
		}

		for (int i = Nk; i < w.length; i++) {
			byte[] temp = w[i - 1];
			if (i % Nk == 0) {
				temp = Bytes.xor(SubWord(RotWord(temp)), Rcon[i / Nk]);
			} else if (Nk > 6 && i % Nk == 4) {
				temp = SubWord(temp);
			}
			w[i] = Bytes.xor(w[i - Nk], temp);
		}

		return w;
	}

	/**
	 * Inverse Cipher: "Series of transformations that converts ciphertext to plaintext using the Cipher Key" (page 6).
	 * Specified in Sec. 5.3.
	 * @param in ciphertext block to decrypt
	 * @return message block
	 */
	public byte[] decrypt(byte[] in) {
		assert in.length == WORD_SIZE * Nb;
		assert w.length == Nb * (Nr + 1);
		byte[][] state = new byte[WORD_SIZE][Nb];
		for (int r = 0; r < WORD_SIZE; r++) {
			for (int c = 0; c < Nb; c++) {
				state[r][c] = in[r + WORD_SIZE * c];
			}
		}
		AddRoundKey(state, Arrays.copyOfRange(w, Nr * Nb, (Nr + 1) * Nb - 1 + 1));
		for (int round = Nr - 1; round >= 1; round--) {
			InvShiftRows(state);
			InvSubBytes(state);
			AddRoundKey(state, Arrays.copyOfRange(w, round * Nb, (round + 1) * Nb - 1 + 1));
			InvMixColumns(state);
		}
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(state, Arrays.copyOfRange(w, 0, Nb - 1 + 1));

		byte[] out = new byte[in.length];
		for (int r = 0; r < WORD_SIZE; r++) {
			for (int c = 0; c < Nb; c++) {
				out[r + WORD_SIZE * c] = state[r][c];
			}
		}
		return out;
	}

	/**
	 * "Transformation in the Inverse Cipher that is the inverse of ShiftRows()" (page 6).
	 * Specified in Sec. 5.3.1.
	 */
	static void InvShiftRows(byte[][] state) {
		for (int r = 1; r < state.length; r++) {
			byte[] newRow = new byte[state[r].length];
			for (int c = 0; c < Nb; c++) {
				newRow[(c + r) % Nb] = state[r][c];
			}
			state[r] = newRow;
		}
	}

	/**
	 * "Transformation in the Inverse Cipher that is the inverse of SubBytes()" (page 6).
	 * Specified in Sec. 5.3.2.
	 */
	static void InvSubBytes(byte[][] state) {
		for (int r = 0; r < WORD_SIZE; r++) {
			for (int c = 0; c < Nb; c++) {
				state[r][c] = INV_S_BOX[state[r][c] & BYTE_MASK];
			}
		}
	}

	/**
	 * "Transformation in the Inverse Cipher that is the inverse of MixColumns()" (page 6).
	 * Specified in Sec. 5.3.3.
	 */
	static void InvMixColumns(byte[][] state) {
		for (int c = 0; c < Nb; c++) {
			byte[] newColumn = new byte[WORD_SIZE];
			newColumn[0] = (byte) (mult((byte) 0xe, state[0][c]) ^ mult((byte) 0xb, state[1][c]) ^ mult((byte) 0xd, state[2][c]) ^ mult((byte) 0x9, state[3][c]));
			newColumn[1] = (byte) (mult((byte) 0x9, state[0][c]) ^ mult((byte) 0xe, state[1][c]) ^ mult((byte) 0xb, state[2][c]) ^ mult((byte) 0xd, state[3][c]));
			newColumn[2] = (byte) (mult((byte) 0xd, state[0][c]) ^ mult((byte) 0x9, state[1][c]) ^ mult((byte) 0xe, state[2][c]) ^ mult((byte) 0xb, state[3][c]));
			newColumn[3] = (byte) (mult((byte) 0xb, state[0][c]) ^ mult((byte) 0xd, state[1][c]) ^ mult((byte) 0x9, state[2][c]) ^ mult((byte) 0xe, state[3][c]));
			for (int r = 0; r < newColumn.length; r++) {
				state[r][c] = newColumn[r];
			}
		}
	}

	enum AESMode {
		// Supported Key-Round combinations
		AES128(128, 10),
		AES192(192, 12),
		AES256(256, 14);

		/** Key length in bytes */
		private final int keyLength;
		/** "Number of 32-bit words comprising the Cipher Key" (page 7). */
		private final int Nk;
		/** "Number of rounds, which is a function of Nk and Nb (which is fixed)" (page 7). */
		private final int Nr;

		AESMode(int keyLengthBits, int Nr) {
			keyLength = keyLengthBits / 8;
			Nk = keyLength / WORD_SIZE;
			this.Nr = Nr;
		}
	}
}
