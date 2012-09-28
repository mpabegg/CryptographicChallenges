package br.ufrgs.seguranca.cryptography;

import java.util.concurrent.Callable;

public class Worker implements Callable<String> {

	private Hexadecimal encodedMessage;
	private String partialKey;

	private AsciiKeyGenerator keyGenerator;
	private ECBCipher cipher;
	
	private String bestKey;
	private int bestKeyEvaluationPoints;

	public Worker(String encodedMessage, String partialKey, int keySuffixSize, int lower, int upper) {

		this.encodedMessage = new Hexadecimal().setValue(encodedMessage);
		this.partialKey = partialKey;

		cipher = new ECBCipher();
		keyGenerator = new AsciiKeyGenerator(keySuffixSize, lower, upper);
	}

	public String call() throws Exception {

		while (keyGenerator.hasNext()) {
		
			String next = keyGenerator.next();
			String key = partialKey + next;

			String decodedMessage = cipher.decrypt(encodedMessage, key);
			
			int decodedMessageEvaluationPoints = MessageEvaluator.evaluate(decodedMessage);
			if (decodedMessageEvaluationPoints >= bestKeyEvaluationPoints && decodedMessageEvaluationPoints > 5) {
				bestKey = key;
				bestKeyEvaluationPoints = decodedMessageEvaluationPoints;
				
				System.out.println(String.format("Message decoded with key %s \n Scored %s:\n\nDecoded Message:\n %s\n -----------------------------", key, bestKeyEvaluationPoints, decodedMessage) );
			}
		}

		return bestKey;
	}
}
