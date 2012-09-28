package br.ufrgs.seguranca.cryptography;

import java.io.FileNotFoundException;
import java.util.concurrent.ExecutionException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

/**
 * Unit test dor {@link BruteForceDecoder}
 * 
 * @author diego
 * @since Sep 17, 2011
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class BruteForceDecoderTest {

	@Test
	public void decoderShouldUserOneWorkerPerAvaiableCPU() throws FileNotFoundException, InterruptedException, ExecutionException {
		
		String encodedMessage = 
				"8BC9CE6925DFA7D82125399C4D4A54B2" +
				"1450B029705D13006B3D1FE1AA0EBE9B" +
				"B4AB19A643D2DA20CEB88C124D17E852" +
				"0DCB22C6BA01F2628311904D2FD674BC" +
				"E3E61EF13F0718300D6E852B5E1EC74C" +
				"8CAE56361714FBE8FD6775B73FAA3714" +
				"6D5ED72B3D00B3DFA6AC23F3E0F59A64" +
				"391F99366E966DB41EEDFF7A690BD20A" +
				"BB24D183440E5557D3E6FEF6D3EB1593" +
				"AE3F5C2EF6C7108FF9B7A75AD7A7E28F" +
				"83ABF348792C20E142F39F8E689D8D35" +
				"B9363570C504B2076BC9E0F08D836A77" +
				"3FB854175C16F33071A69F143C68BD8F" +
				"C0D3E28402AF789DF8D228018DF3D1BE" +
				"D29AC0A4085B6A9B7EFDCCC3F9DD3279" +
				"714C5D42CE1351B11FD5F0E90FADB385" +
				"C4B35F72294E001B3E503D73359EDA64" +
				"5543FED3344CD537102118ACA0650263";
		
		String weberText= "546578746F2070617261207465737465";
		
		BruteForceDecoder decoder = new BruteForceDecoder(weberText, "essasenhaehfra");
		decoder.setMissingKeySuffixSize(2);
		decoder.decode1();
		
	}
	
	@Test
	public void shouldWriteResultIntoFile() throws Exception {
		
		BruteForceDecoder.writeToFile("essasenhaehfraca", "A506A19333F306AC2C62CBE931963AE7");
	}
}
