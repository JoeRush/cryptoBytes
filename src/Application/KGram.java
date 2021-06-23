package Application;
/**
 * Cryptogram when using KeyPairs
 * @author Joseph Rushford
 * @author Matthew Molina
 *
 */
public class KGram {
	private EllipticPoint myZ;
	private byte[] myC;
	private byte[] myT;
	/**
	 * constructor for the cryptogram
	 * @param Z encoded random number
	 * @param c encoded message
	 * @param t test case
	 */
	public KGram(EllipticPoint Z, byte[] c, byte[] t) {
		
		// TODO Auto-generated constructor stub
	
		myZ = Z;
		myC = c;
		myT = t;
	}
	/** 
	 * random number as a Point
	 * @return random number
	 */ 
	public EllipticPoint getZ() {
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
