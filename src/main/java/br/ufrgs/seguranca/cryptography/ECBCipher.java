package br.ufrgs.seguranca.cryptography;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class ECBCipher {

	private static final String CHARSET = "UTF-8";
	private static final String ALGORITHM = "AES";
	private static final String MODE = "ECB/NOPADDING";

	public Hexadecimal encrypt(String plainTextMessage, String secretKey) throws Exception{
		Key key = new SecretKeySpec(secretKey.getBytes(CHARSET), ALGORITHM);

		Cipher c = Cipher.getInstance(ALGORITHM + "/" + MODE);

		c.init(Cipher.ENCRYPT_MODE, key);

		return new Hexadecimal(c.doFinal(plainTextMessage.getBytes()));
	}

	public String decrypt(Hexadecimal ecryptedMessage, String secretKey) throws Exception{
		Key key = new SecretKeySpec(secretKey.getBytes(CHARSET), ALGORITHM);

		Cipher c = Cipher.getInstance(ALGORITHM + "/" + MODE);

		c.init(Cipher.DECRYPT_MODE, key);

		return new String(c.doFinal(ecryptedMessage.asByteArray()));
	}

}
