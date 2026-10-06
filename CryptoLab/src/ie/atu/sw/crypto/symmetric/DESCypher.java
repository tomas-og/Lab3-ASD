package ie.atu.sw.crypto.symmetric;

import javax.crypto.*;

import ie.atu.sw.crypto.AbstractCypher;

public class DESCypher extends AbstractCypher{
	public DESCypher() throws Throwable{
		KeyGenerator keyGen = KeyGenerator.getInstance("DES");
		keyGen.init(56);
		super.setKey(keyGen.generateKey());
		super.setCypher(Cipher.getInstance("DES/ECB/PKCS5Padding"));
		
		System.out.println(super.getKey().getAlgorithm());
		System.out.println(super.getKey().getFormat());
		System.out.println(super.getKey().getEncoded());
	}
}
