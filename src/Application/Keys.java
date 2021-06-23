package Application;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Keys {
	public static PrivateKey loadPrivateKey(String key) throws GeneralSecurityException {
		byte[] data = Base64.getDecoder().decode(key.getBytes());
		PKCS8EncodedKeySpec keyS = new PKCS8EncodedKeySpec(data);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		PrivateKey privateK = factory.generatePrivate(keyS);
		return privateK;
		
	}
	public static PublicKey loadPublicKey(String key) throws GeneralSecurityException {
		byte[] data = Base64.getDecoder().decode(key.getBytes());
		X509EncodedKeySpec keyS = new X509EncodedKeySpec(data);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		return factory.generatePublic(keyS);
	}
	public static String getPublic(PublicKey publicK) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory factory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec spec = factory.getKeySpec(publicK, X509EncodedKeySpec.class);
		return Base64.getEncoder().encodeToString((spec.getEncoded()));
	}
	public static String getPrivate(PrivateKey privateK) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory factory = KeyFactory.getInstance("RSA");
	    PKCS8EncodedKeySpec spec = factory.getKeySpec(privateK,
	            PKCS8EncodedKeySpec.class);
	    byte[] packed = spec.getEncoded();
	    String key64 = Base64.getEncoder().encodeToString(packed);

	    Arrays.fill(packed, (byte) 0);
	    return key64;

	}
	
}
