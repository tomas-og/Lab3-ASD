package ie.atu.sw;

import javax.crypto.*;

public class AESCypher extends AbstractCypher{
	public AESCypher() throws Throwable{
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		super.setKey(keyGen.generateKey());
		super.setCypher(Cipher.getInstance("AES/ECB/PKCS5Padding"));
	}
}
