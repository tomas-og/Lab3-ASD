package ie.atu.sw.crypto;

import java.security.*;

import javax.crypto.Cipher;

public abstract class AbstractCypher implements Cypherable {
	private Cipher cypher;
	private Key key;

	public AbstractCypher() {
		super();
	}

	public byte[] encrypt(byte[] plainText) throws Throwable {
		getCypher().init(Cipher.ENCRYPT_MODE, key);
		return getCypher().doFinal(plainText);
	}

	public byte[] decrypt(byte[] cypherText) throws Throwable {
		getCypher().init(Cipher.DECRYPT_MODE, key);
		return getCypher().doFinal(cypherText);
	}

	protected Cipher getCypher() {
		return cypher;
	}

	protected void setCypher(Cipher cypher) {
		this.cypher = cypher;
	}

	protected Key getKey() {
		return key;
	}

	protected void setKey(Key useKey) {
		this.key = useKey;
	}
}