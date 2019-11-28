package net.markenwerk.utils.mail.dkim;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

class Utils {

	static String randomString(Random random, int length) {
		char[] chars = new char[length];
		for (int i = 0; i < length; i++) {
			int v = random.nextInt(0x60 + 6); // [0x20, 0x7f] + ctrl*6
			char c;
			if (v == 0) {
				c = '\r'; // carriage return
			} else if (v == 1) {
				c = '\n'; // line feed
			} else if (v == 2) {
				c = ' '; // space
			} else if (v == 3) {
				c = '\f'; // vertical tab
			} else if (v == 4) {
				c = '\u000b'; // form feed
			} else if (v == 5) {
				c = '\t'; // horizontal tab
			} else {
				c = (char) (v - 6 + 0x20); // [0x20, 0x7f]
			}
			chars[i] = c;
		}
		return new String(chars);
	}

	static byte[] read(File file) throws IOException {
		FileInputStream inputStream = new FileInputStream(file);
		byte[] bytes = inputStream.readAllBytes();
		inputStream.close();
		return bytes;
	}

	static void write(File file, byte[] bytes) throws IOException {
		new ByteArrayInputStream(bytes).transferTo(new FileOutputStream(file));
	}

	static String digest(String string, String algorithm) throws IOException, NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance(algorithm);
		DigestOutputStream out = new DigestOutputStream(OutputStream.nullOutputStream(), digest);
		new ByteArrayInputStream(string.getBytes()).transferTo(out);
		return java.util.Base64.getEncoder().encodeToString(digest.digest());
	}

	static DkimSigner getSigner(Canonicalization canonicalization, SigningAlgorithm algorithm) throws Exception {

		DkimSigner signer = new DkimSigner("example.com", "dkim1", new File("./src/test/resources/key/dkim.der"));
		signer.setHeaderCanonicalization(canonicalization);
		signer.setBodyCanonicalization(canonicalization);
		signer.setLengthParam(true);
		signer.setSigningAlgorithm(algorithm);
		signer.setZParam(false);
		signer.setCheckDomainKey(false);

		return signer;

	}

}
