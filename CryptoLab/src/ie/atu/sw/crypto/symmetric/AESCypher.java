package ie.atu.sw.crypto.symmetric;

import javax.crypto.*;

import ie.atu.sw.crypto.AbstractCypher;

public class AESCypher extends AbstractCypher{
	public AESCypher() throws Throwable{
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		super.setKey(keyGen.generateKey());
		super.setCypher(Cipher.getInstance("AES/ECB/PKCS5Padding"));
	}
}
