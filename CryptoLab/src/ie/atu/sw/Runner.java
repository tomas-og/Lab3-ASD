package ie.atu.sw;

import ie.atu.sw.crypto.Algorithm;
import ie.atu.sw.crypto.CypherFactory;
import ie.atu.sw.crypto.Cypherable;

public class Runner {
	public static void main(String[] args) throws Throwable{
		CypherFactory cf = CypherFactory.getInstance();
		Cypherable cypher = cf.getCypherable(Algorithm.VIGENERE);
		
		
		byte[] s = new String("HAPPY DAYS").getBytes("UTF-8");
		byte[] t = cypher.encrypt(s);
		
		System.out.println(new String(t));
		System.out.println(new String(cypher.decrypt(t)));
	}
}