package ie.atu.sw.crypto;

import ie.atu.sw.crypto.asymmetric.RSACypher;
import ie.atu.sw.crypto.symmetric.AESCypher;
import ie.atu.sw.crypto.symmetric.DESCypher;
import ie.atu.sw.crypto.symmetric.VigenereCypher;

public class CypherFactory { // A singleton factory....
	//The static class field can see the private constructor
	private static CypherFactory fact = new CypherFactory();
	
	//Make the constructor private
	private CypherFactory(){		
	}
	
	//Use a static method to get a handle on the single instance of the class
	public static CypherFactory getInstance(){
		return fact;
	}
	
	//This is the factory method
	public Cypherable getCypherable(Algorithm algo) throws Throwable{
		/* All of this logic could be replaced by a command object, as there is an
		 * unbounded number of possible cryptographic algorithms to use. The intent of a command
		 * object is to "encapsulate a method invocation", which is exactly what we want 
		 * to do here... More on this later!
		 */
		return switch(algo) {
			case AES -> new AESCypher();
			case DES -> new DESCypher();
			case CAESAR, VIGENERE -> {
				VigenereCypher vc =  new VigenereCypher();
				vc.setKey("OBJECT ORIENTED SOFTWARE DEVELOPMENT");
				yield vc;
			}
			case RSA -> new RSACypher();
		};
	}
}
