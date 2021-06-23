package Application;
/**
 * Signature of data
 * @author Joseph Rushford
 * @author Matthew Molina
 *
 */
public class Signature {
	private byte[] myH;
	private byte[] myZ;
	/** 
	 * constructor for a signature
	 * @param h of the signature
	 * @param z of the signature
	 */
	public Signature(byte[] h, byte[] z) {
		myH = h;
		myZ = z;
	}
	/**
	 * gets the h value of signature
	 * @return h 
	 */
	public byte[] getH() {
		return myH;
	}
	/**
	 * gets the z value of signature
	 * 
	 * @return z
	 */
	public byte[] getZ() {
		return myZ;
	}
}
