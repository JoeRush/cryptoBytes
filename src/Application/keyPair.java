package Application;
import java.math.BigInteger;
/**
 * key pair for encryption
 * @author Joseph Rushford
 * @author Matthew Molina
 *
 */
public class keyPair {
	private EllipticPoint myPublic;
	private BigInteger myPrivate;
	/**
	 * constructor when given the public and private keys
	 * @param privateK
	 * @param publicK
	 */
	keyPair(BigInteger privateK, EllipticPoint publicK) {
		myPublic = publicK;
		myPrivate = privateK;
	}
	/**
	 * gets the public key
	 * @return public key EllipticPoint
	 */
	public EllipticPoint getPublic() {
		return myPublic;
	}
	/**
	 * gets the private key
	 * @return private key EllipticPoint
	 */
	public BigInteger getPrivate() {
		return myPrivate;
	}
}
