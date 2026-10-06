package ie.atu.sw.crypto.asymmetric;

import java.security.*;
import javax.crypto.*;

import ie.atu.sw.crypto.AbstractCypher;

public class RSACypher extends AbstractCypher {
	private KeyPair keyRing;
	public RSACypher() throws Throwable{
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA"); //Singleton
		keyGen.initialize(2048);
		keyRing = keyGen.generateKeyPair();
		setCypher(Cipher.getInstance("RSA/ECB/PKCS1Padding"));//Singleton + factoryish...
		super.setKey(keyRing.getPublic());
	}
	
	public byte[] encrypt(byte[] plainText) throws Throwable {
		setKey(super.getKey());
		return super.encrypt(plainText);
	}

	public byte[] decrypt(byte[] cypherText) throws Throwable {
		setKey(super.getKey());
		return super.decrypt(cypherText);
	}

	protected void setKey(Key key) {
		if (key instanceof PublicKey){
			super.setKey(keyRing.getPrivate());
		}else{
			super.setKey(keyRing.getPublic());
		}
	}
}