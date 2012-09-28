package br.ufrgs.seguranca.cryptography;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Before;
import org.junit.Test;

public class ECBCipherTest {

	private ECBCipher cipher;

	@Before
	public void setUp() {
		cipher = new ECBCipher();
	}

	@Test
	public void itEcryptsAPlainTextToHexadecimal() throws Exception {
		assertThat(cipher.encrypt("Texto para teste", "essasenhaehfraca"),
				is(new Hexadecimal()
						.setValue("A506A19333F306AC2C62CBE931963AE7")));
	}

	@Test
	public void itDecryptsAnHexadecimalMessageToPlainText() throws Exception {
		assertThat(cipher.decrypt(
				new Hexadecimal().setValue("A506A19333F306AC2C62CBE931963AE7"),
				"essasenhaehfraca"), is("Texto para teste"));
	}
	
	@Test
	public void gimmeTheCryptedText() throws Exception {
		
		String plainTextMessage = 
				"A zarabatana (or" +
				"iginaria da pala" +
				"vra arabe zaraba" +
				"tan) e uma arma " +
				"que consiste num" +
				" tubo originalme" +
				"nte de madeira (" +
				"caule oco), e ho" +
				"je de metal ou p" +
				"lastico, pelo qu" +
				"al sao soprados " +
				"pequenos dardos," +
				" setas ou projec" +
				"teis. A zarabata" +
				"na e uma arma, n" +
				"ao um brinquedo," +
				" podendo infligi" +
				"r danos graves. ";
		
		System.out.println(cipher.encrypt(plainTextMessage, "Key2Group19000R9"));
	}
}
