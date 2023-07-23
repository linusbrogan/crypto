package com.linusbrogan.pkg.crypto;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class AESTest {
	// Key Expansion Examples (App. A)
	// Expansion of a 128-bit Cipher Key (A.1)
	private static final byte[] CIPHER_KEY_128b = Bytes.convertHexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
	private static final byte[][] w_128b = convertHexToWordArray("2b7e151628aed2a6abf7158809cf4f3ca0fafe1788542cb123a339392a6c7605f2c295f27a96b9435935807a7359f67f3d80477d4716fe3e1e237e446d7a883bef44a541a8525b7fb671253bdb0bad00d4d1c6f87c839d87caf2b8bc11f915bc6d88a37a110b3efddbf98641ca0093fd4e54f70e5f5fc9f384a64fb24ea6dc4fead27321b58dbad2312bf5607f8d292fac7766f319fadc2128d12941575c006ed014f9a8c9ee2589e13f0cc8b6630ca6");
	// Expansion of a 192-bit Cipher Key (A.2)
	private static final byte[] CIPHER_KEY_192b = Bytes.convertHexToBytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
	private static final byte[][] w_192b = convertHexToWordArray("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7bfe0c91f72402f5a5ec12068e6c827f6b0e7a95b95c56fec24db7b4bd69b5411885a74796e92538fde75fad44bb095386485af05721efb14fa448f6d94d6dce24aa326360113b30e6a25e7ed583b1cf9a27f939436a94f767c0a69407d19da4e1ec1786eb6fa64971485f703222cb8755e26d135233f0b7b340beeb282f18a2596747d26b458c553ea7e1466c9411f1df821f750aad07d753ca4005388fcc5006282d166abc3ce7b5e98ba06f448c773c8ecc720401002202");
	// Expansion of a 256-bit Cipher Key (A.3)
	private static final byte[] CIPHER_KEY_256b = Bytes.convertHexToBytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
	private static final byte[][] w_256b = convertHexToWordArray("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff49ba354118e6925afa51a8b5f2067fcdea8b09c1a93d194cdbe49846eb75d5b9ad59aecb85bf3c917fee94248de8ebe96b5a9328a2678a647983122292f6c79b3812c81addadf48ba24360af2fab8b46498c5bfc9bebd198e268c3ba709e0421468007bacb2df331696e939e46c518d80c814e20476a9fb8a5025c02d59c58239de1369676ccc5a71fa2563959674ee155886ca5d2e2f31d77e0af1fa27cf73c3749c47ab18501ddae2757e4f7401905acafaaae3e4d59b349adf6acebd10190dfe4890d1e6188d0b046df344706c631e");

	private static byte[][] convertHexToWordArray(String hex) {
		int wordSize = 4;
		byte[] bytes = Bytes.convertHexToBytes(hex);
		byte[][] words = new byte[bytes.length / wordSize][wordSize];
		for (int i = 0; i < bytes.length; i++) {
			words[i / 4][i % 4] = bytes[i];
		}
		return words;
	}

	@Test
	void expandsKeys() {
		assertArrayEquals(w_128b, new AES(CIPHER_KEY_128b).KeyExpansion(CIPHER_KEY_128b));
		assertArrayEquals(w_192b, new AES(CIPHER_KEY_192b).KeyExpansion(CIPHER_KEY_192b));
		assertArrayEquals(w_256b, new AES(CIPHER_KEY_256b).KeyExpansion(CIPHER_KEY_256b));
	}

	@Test
	void substitutesWordsPurely() {
		byte[] before = {0x32, (byte) 0xab, (byte) 0x97, (byte) 0xa1};
		byte[] beforeCopy = Arrays.copyOf(before, before.length);
		byte[] after = {0x23, 0x62, (byte) 0x88, 0x32};
		assertArrayEquals(after, AES.SubWord(before));
		assertArrayEquals(beforeCopy, before);
	}

	@Test
	void rotatesWordsPurely() {
		byte[] before = {10, 14, -3, 6};
		byte[] beforeCopy = Arrays.copyOf(before, before.length);
		byte[] after = {14, -3, 6, 10};
		assertArrayEquals(after, AES.RotWord(before));
		assertArrayEquals(beforeCopy, before);
	}

	// Cipher Example (App. B)
	byte[] CIPHER_INPUT = Bytes.convertHexToBytes("3243f6a8885a308d313198a2e0370734");
	byte[] CIPHER_KEY = Bytes.convertHexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
	// Output block column-by-column (page 34)
	byte[] CIPHER_OUTPUT = Bytes.convertHexToBytes("3925841d02dc09fbdc118597196a0b32");

	@Test
	void encrypts() {
		AES aes = new AES(CIPHER_KEY);
		assertArrayEquals(CIPHER_OUTPUT, aes.encrypt(CIPHER_INPUT));
	}

	// Intermediate State values (page 33)
	String[] STATES = {
		"19a09ae93df4c6f8e3e28d48be2b2a08", // Round 1, Start of Round
		"d4e0b81e27bfb44111985d52aef1e530", // Round 1, After SubBytes
		"d4e0b81ebfb441275d52119830aef1e5", // Round 1, After ShiftRows
		"04e0482866cbf8068119d326e59a7a4c", // Round 1, After MixColumns
		"a0fafe1788542cb123a339392a6c7605", // Round 1, Round Key Value
		"a4686b029c9f5b6a7f35ea50f22b4349" // Round 2, Start of Round
	};

	@Test
	void substitutesBytes() {
		int step = 0;
		byte[][] before = convertHexToWordArray(STATES[step]);
		byte[][] after = convertHexToWordArray(STATES[step + 1]);
		AES.SubBytes(before);
		assertArrayEquals(after, before);
	}

	@Test
	void shiftsRows() {
		int step = 1;
		byte[][] before = convertHexToWordArray(STATES[step]);
		byte[][] after = convertHexToWordArray(STATES[step + 1]);
		AES.ShiftRows(before);
		assertArrayEquals(after, before);
	}

	@Test
	void mixesColumns() {
		int step = 2;
		byte[][] before = convertHexToWordArray(STATES[step]);
		byte[][] after = convertHexToWordArray(STATES[step + 1]);
		AES.MixColumns(before);
		assertArrayEquals(after, before);
	}

	@Test
	void multipliesBytes() {
		// Products from page 11
		assertEquals((byte) 0xc1, AES.mult((byte) 0x57, (byte) 0x83));
		assertEquals((byte) 0xfe, AES.mult((byte) 0x57, (byte) 0x13));
	}

	@Test
	void multipliesByX() {
		// Products from page 12
		byte[] actual = {0x57, (byte) 0xae, 0x47, (byte) 0x8e};
		for (int i = 0; i < actual.length; i++) {
			actual[i] = AES.xtime(actual[i]);
		}
		byte[] expected = {(byte) 0xae, 0x47, (byte) 0x8e, 0x07};
		assertArrayEquals(expected, actual);
	}

	@Test
	void addsRoundKey() {
		int step = 3;
		byte[][] before = convertHexToWordArray(STATES[step]);
		byte[][] roundKey = convertHexToWordArray(STATES[step + 1]);
		byte[][] after = convertHexToWordArray(STATES[step + 2]);
		AES.AddRoundKey(before, roundKey);
		assertArrayEquals(after, before);
	}

	@Test
	void decrypts() {
		AES aes = new AES(CIPHER_KEY);
		assertArrayEquals(CIPHER_INPUT, aes.decrypt(CIPHER_OUTPUT));
	}

	@Test
	void inverseSubstitutesBytes() {
		int step = 0;
		byte[][] before = convertHexToWordArray(STATES[step + 1]);
		byte[][] after = convertHexToWordArray(STATES[step]);
		AES.InvSubBytes(before);
		assertArrayEquals(after, before);
	}

	@Test
	void inverseShiftsRows() {
		int step = 1;
		byte[][] before = convertHexToWordArray(STATES[step + 1]);
		byte[][] after = convertHexToWordArray(STATES[step]);
		AES.InvShiftRows(before);
		assertArrayEquals(after, before);
	}

	@Test
	void inverseMixesColumns() {
		int step = 2;
		byte[][] before = convertHexToWordArray(STATES[step + 1]);
		byte[][] after = convertHexToWordArray(STATES[step]);
		AES.InvMixColumns(before);
		assertArrayEquals(after, before);
	}

	@Test
	void selectsCorrectModeForKey() {
		byte[][] keys = {CIPHER_KEY_128b, CIPHER_KEY_192b, CIPHER_KEY_256b, new byte[512], new byte[64]};
		AES.AESMode[] modes = {AES.AESMode.AES128, AES.AESMode.AES192, AES.AESMode.AES256, null, null};
		for (int i = 0; i < keys.length; i++) {
			assertEquals(modes[i], AES.selectModeForKey(keys[i].length));
		}
	}
}
