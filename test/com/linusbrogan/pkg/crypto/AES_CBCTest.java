package com.linusbrogan.pkg.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AES_CBCTest {
	private static final byte[] KEY = Bytes.convertHexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
	private static final byte[] IV = Bytes.convertHexToBytes("3243f6a8885a308d313198a2e0370734");
	private static final byte[] M0 = Bytes.convertHexToBytes("546869732069732061206d6573736167652e2049742077696c6c20626520656e637279707465642e2059617921");
	private static final byte[] C0 = Bytes.convertHexToBytes("3243f6a8885a308d313198a2e0370734993a3e74628b7e6209de5cfb7aa5bc0b65c83f5e7e8028588f4e7c7e1e72223308267cecf16b0424a6c0c00fbabf086d");
	private static final byte[] M1 = Bytes.convertHexToBytes("5468697320697320616e6f74686572206d6573736167652e2059697070656521");
	private static final byte[] C1 = Bytes.convertHexToBytes("3243f6a8885a308d313198a2e037073464ade8df7c6ef2959a6301242b160856b32e464233d5d8727a1760b6b081cb56e1d844049d57df1f921f1b8a15f0d5fc");
	private static final byte[] M2 = {};
	private static final byte[] C2 = Bytes.convertHexToBytes("3243f6a8885a308d313198a2e0370734f6c7cfe173c8a95054e5f36b0a498d77");
	private static final AES_CBC CBC = new AES_CBC(KEY);

	@Test
	void encryptsUnalignedMessage() {
		assertArrayEquals(C0, CBC.encrypt(IV, M0));
	}

	@Test
	void encryptsAlignedMessage() {
		assertArrayEquals(C1, CBC.encrypt(IV, M1));
	}

	@Test
	void encryptsEmptyMessage() {
		assertArrayEquals(C2, CBC.encrypt(IV, M2));
	}

	@Test
	void decryptsUnalignedMessage() {
		assertArrayEquals(M0, CBC.decrypt(C0));
	}

	@Test
	void decryptsAlignedMessage() {
		assertArrayEquals(M1, CBC.decrypt(C1));
	}

	@Test
	void decryptsEmptyMessage() {
		assertArrayEquals(M2, CBC.decrypt(C2));
	}
}
