package Application;
/**
 * Cryptogram formed from data encoded under a passphrase
 * @author Joseph Rushford
 * @author Matthew Molina
 */
public class Cryptogram {
	private int myZ;
	private byte[] myC;
	private byte[] myT;
	public Cryptogram(int z ,byte[] c, byte[] t) {
		myZ = z;
		myC = c;
		myT = t;
	}
	/** 
	 * random number
	 * @return random number
	 */
	public int getZ() {
		return myZ;
	}
	/**
	 * encoded message
	 * @return encoded message
	 */
	public byte[] getC() {
		return myC;
	}
	/**
	 * test case
	 * @return test case 
	 */
	public byte[] getT() {
		return myT;
	}
}
