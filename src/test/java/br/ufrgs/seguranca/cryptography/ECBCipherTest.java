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
}
