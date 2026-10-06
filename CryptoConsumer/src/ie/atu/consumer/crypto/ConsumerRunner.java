package ie.atu.consumer.crypto;

import ie.atu.sw.crypto.*;
import ie.atu.sw.crypto.Cypherable;
import ie.atu.sw.crypto.symmetric.AESCypher;
import ie.atu.sw.crypto.symmetric.VigenereCypher;

//javac --release 25 -d .\bin --module-path "..\CryptoLab\crypto.jar" .\src\module-info.java .\src\ie\atu\consumer\crypto\ConsumerRunner.java
//java --module-path ".\bin;..\CryptoLab\crypto.jar" --module atu.consumer/ie.atu.consumer.crypto.ConsumerRunner


public class ConsumerRunner {
	public static void main(String[] args) throws Throwable {
		CypherFactory cf = CypherFactory.getInstance();
		//Cypherable cypher = new VigenereCypher();
		Cypherable cypher = new AESCypher();
		//Cypherable cypher = cf.getCypherable(Algorithm.AES);
		byte[] s = new String("HAPPY DAYS").getBytes("UTF-8");
		byte[] t = cypher.encrypt(s);
		System.out.println(new String(t));
		System.out.println(new String(cypher.decrypt(t)));
	}
}
