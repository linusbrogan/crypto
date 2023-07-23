package com.linusbrogan.pkg.crypto;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class AES_CTRTest {
	private static final byte[] KEY = Bytes.convertHexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
	private static final byte[] IV = Bytes.convertHexToBytes("3243f6a8885a308d313198a2e0370734");
	private static final byte[] M0 = Bytes.convertHexToBytes("546869732069732061206d6573736167652e2049742077696c6c20626520656e637279707465642e2059617921");
	private static final byte[] C0 = Bytes.convertHexToBytes("3243f6a8885a308d313198a2e03707346d4ded6e22b57adbbd31e8f26a196a55558c7d2328b5aa8b556b78d335df15562b6873dc1d278e5162345b22f5");
	private static final byte[] M1 = Bytes.convertHexToBytes("5468697320697320616e6f74686572206d6573736167652e2059697070656521");
	private static final byte[] C1 = Bytes.convertHexToBytes("3243f6a8885a308d313198a2e03707346d4ded6e22b57adbbd7feae3710f79125dc72e193df2b8cc195e31c1209a1519");
	private static final byte[] M2 = {};
	private static final byte[] C2 = IV;
	private static final AES_CTR CTR = new AES_CTR(KEY);

	@Test
	void encryptsUnalignedMessage() {
		assertArrayEquals(C0, CTR.encrypt(IV, M0));
	}

	@Test
	void encryptsAlignedMessage() {
		assertArrayEquals(C1, CTR.encrypt(IV, M1));
	}

	@Test
	void encryptsEmptyMessage() {
		assertArrayEquals(C2, CTR.encrypt(IV, M2));
	}

	@Test
	void decryptsUnalignedMessage() {
		assertArrayEquals(M0, CTR.decrypt(C0));
	}

	@Test
	void decryptsAlignedMessage() {
		assertArrayEquals(M1, CTR.decrypt(C1));
	}

	@Test
	void decryptsEmptyMessage() {
		assertArrayEquals(M2, CTR.decrypt(C2));
	}

	@Test
	void incrementsBlockPurely() {
		byte[] before = Bytes.convertHexToBytes("2b7e151628aed2a6abf7158809cfffff");
		byte[] beforeCopy = Arrays.copyOf(before, before.length);
		byte[] after = Bytes.convertHexToBytes("2b7e151628aed2a6abf7158809d00000");
		assertArrayEquals(after, AES_CTR.incrementBlock(before));
		assertArrayEquals(beforeCopy, before);
	}
}
