package Application;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
/**
 * Main Cryptographic class that features parts 1-5
 * part one methods of rotl, sha_keccakf, sha_init, sha_update , sha_final , shaH,
 * shake128_init, shake256_init , shake_xof , and shake_out inspired by
 * https://github.com/mjosaarinen/tiny_sha3
 * @author Joseph Rushford
 * @author Matthew Molina
 *
 */

public class sha3 {
	
	private static int keccakf_rounds = 24;
	/**
	 * influenced by https://github.com/mjosaarinen/tiny_sha3
	 * ROTL64
	 * @param x long value that is being bit shifted
	 * @param y long value that is used to bit shift
	 * @return x bitshifted;
	 */
	private static long rotl64(long x, long y) {
		long s =(((x) << (y)) | ((x) >>> (64 - (y))));
		

		//System.out.println(s);
		return s;
		
	}
	/**
	 * influenced by https://github.com/mjosaarinen/tiny_sha3
	 * KECCAK algorithm
	 * @param ms the data that KECCAK is to encode
	 */
	private static void sha3_keccakf(long[] ms) {
		//major issue
		String keccakf_rndc[] = {
				 "1", "32898",
			     "9223372036854808714", "9223372039002292224", 
			     "32907", "2147483649",
			     "9223372039002292353", "9223372036854808585", 
			     "138", "136",
			     "2147516425", "2147483658", 
			     "2147516555", "9223372036854775947", 
			     "9223372036854808713", "9223372036854808579", 
			     "9223372036854808578", "9223372036854775936",
			     "32778", "9223372039002259466", 
			     "9223372039002292353", "9223372036854808704", 
			     "2147483649", "9223372039002292232"
		};
		
		int keccakf_rotc[] = {
		        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
		        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
		};
	    int keccakf_piln[] = {
	            10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
	            15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
	    };
	    long t;
	    long bc[] = new long[5];
	    for(int i = 0; i < 25; i++) {

	    	ms[i] = Long.reverseBytes(ms[i]);
	 
	    	
	    }
	    for(int i = 0; i < keccakf_rounds; i++) {
	    		// Theta
	  
	    		for(int j = 0; j < 5; j++) {
	
	    			bc[j] = ms[j]^ms[j+5]^ms[j+10]^ms[j+15]^ms[j+ 20];
	    			
	    		}
//	    		System.out.println("-----------");
	    		for(int k = 0; k < 5; k++) {
	    			
	    			int ind = (k+4)%5;
	    	
	    			t = bc[ind]^rotl64(bc[(k + 1) % 5], 1);
	    	
	    			for(int l = 0; l < 25; l+=5) {
	    				ms[k+l] ^= t;
	    			}
	    		}
	    
	    		// Rho Pi
	    		t = ms[1];
	    		//System.out.println("the value of t is " + t);
	    		for(int g = 0; g < 24; g++) {
	    			int s = keccakf_piln[g];
//	    			System.out.println("the value of s is: " + s);
	    			bc[0] = ms[s];
//	    			System.out.println("the value of bc[0] is " + bc[0]);
	    			ms[s] = rotl64(t, keccakf_rotc[g]);
//	    			System.out.println("the value of ms[s] is " + ms[s]);
	    			t = bc[0];
//	    			System.out.println("the value of t is " + t);
//	    			System.out.println("________________");
	    		}
	    		//Chi
	    		for(int f = 0; f < 25; f+=5) {
	    			for(int l = 0; l < 5; l++) {
	    				bc[l] = ms[f + l];
	    			}
	    			for(int j = 0; j < 5; j++) {

	    				ms[j + f]  ^= (~bc[(j+1) % 5]) & bc[(j+2)%5];
	    			}
	    		}

	    		ms[0] ^= Long.parseUnsignedLong(keccakf_rndc[i]);

	    		
	    }

	    for(int i = 0; i < 25; i++) {

	    	
	    	ms[i] = Long.reverseBytes(ms[i]);

	    }
	}
	/**
	 * influenced by https://github.com/mjosaarinen/tiny_sha3
	 * initiates the state
	 * @param theInfo the state to be initiates
	 * @param mdlen the length of the output
	 */
	public static void sha3_init(sha3_ctx_t theInfo, int mdlen) {
		//long q[] = theInfo.getPULongs();
		long q[] = theInfo.getQ();
		for(int i = 0; i < 25; i++) {
			q[i]  = 0;
			
		}

			

		//theInfo.updatePULONGs(q);
		theInfo.setMdlen(mdlen);
		//System.out.println(mdlen);
		//int calc = 200 - (2*mdlen);

		theInfo.setRsize(200 - 2*mdlen);
		//System.out.println("r size is" + theInfo.getRsize());
		theInfo.setPt(0);
	}
	
	/**
	 * updates state with more data
	 * influenced by https://github.com/mjosaarinen/tiny_sha3
	 * @param theInfo current state of data
	 * @param len length of output in bits
	 * @param in data to be put into the state
	 */
	public static void sha3_update(sha3_ctx_t theInfo, long len, byte[] in) {
			int pt = theInfo.getPT();
	
			long[] q = new long[64];
    		byte[] b = theInfo.getB();
			for(int i = 0; i < len; i++) {
		
		
				b[pt++]  ^= in[i];
			
				if(pt >= theInfo.getRsize()) {
					
				
					q = convertByteArrayToArray(b);
					sha3_keccakf(q);
					theInfo.updateQ(q);
					
					b = convertLongArrayToByte(q);
				
					pt = 0;
	
			
				}
				q = convertByteArrayToArray(b);
				theInfo.updateQ(q);
				theInfo.updateB(b);
				
			}
			

			//System.out.println("the values of b are " + Arrays.toString(b));
			//System.out.println("the value of pt is " + pt);
		theInfo.setPt(pt);
	}
	/**
	 * finalizes hash
	 * influenced by https://github.com/mjosaarinen/tiny_sha3
	 * @param md the output
	 * @param theInfo the data state
	 * @return the final data output
	 */
	public static byte[] sha3_final(byte[] md, sha3_ctx_t theInfo) {
		int pt = theInfo.getPT();

		byte b[] = theInfo.getB();
		b[pt] ^= 0x06;
		//System.out.println("the value of at pt " + pt + " is " + b[pt]);
		
		b[theInfo.getRsize() - 1] ^= 0x80;
		//System.out.println("the value of at rsize " + (theInfo.getRsize() -1) + "is" + b[theInfo.getRsize() - 1]);
		
		
		long q[] = convertByteArrayToArray(b);
		
		sha3_keccakf(q);
		theInfo.updateQ(q);
		b = convertLongArrayToByte(q);
		theInfo.updateB(b);
		
		///String hex = "";
		md = Arrays.copyOf(b, theInfo.getMdlen());
//		for(int i = 0; i < theInfo.getMdlen(); i++) {
//			
//			md[i] = b[i];
//			int tem = Byte.toUnsignedInt(b[i]);
//			hex = hex.concat(Integer.toHexString(tem));
//		
//		}
	// bigin = new BigInteger(b);
//		System.out.println("theINfo.get(28) is " + Long.toHexString(Byte.toUnsignedLong(b[28])));

		return md;
	}
	/**
	 * Runs sha3 algorithm
	 * influenced by https://github.com/mjosaarinen/tiny
	 * @param in the input of data
	 * @param inlen the length of the input
	 * @param md the output
	 * @param mdlen the output's requested length
	 * @return the byte array representing the hash of the data given through sha3
	 */
	public static byte[] sha3H(byte[] in, long inlen, byte[] md, int mdlen) {
		sha3_ctx_t sha3 = new sha3_ctx_t();
		
		//BigInteger bigin = new BigInteger(in);



		sha3_init(sha3, mdlen);
		
		sha3_update(sha3, inlen, in);
		//System.out.println("the values in q are" + Arrays.toString(sha3.getQ()));
		md = sha3_final(md, sha3);

		return md;
	}
	/**
	 * Authentication Code for Messages under KECCAK
	 * @param k bytes of key
	 * @param x bytes of input
	 * @param l byte length for output
	 * @param s customization string
	 * @return
	 */
	public static byte[] kmacxof256(byte[] k, byte[] x, int l, String s) {
		
		byte[] kmac  = x;
		int kmacLen = kmac.length;
		byte[] kBytes = bytepad(k, 136);
		int kLen = kBytes.length;
		byte[] rEncode = right_encode(BigInteger.valueOf(0));
		int rLen = rEncode.length;
		if( l >= 0) {
			byte[] newX = new byte[kmacLen + kLen + rLen];
			System.arraycopy(kBytes, 0, newX, 0, kLen);
			System.arraycopy(kmac, 0, newX, kLen, kmacLen);
			System.arraycopy(rEncode, 0, newX, kLen+kmacLen, rLen);
			//byte[] n = {(byte) 210, (byte) 178, (byte) 130, (byte) 194};
			kmac = cshake256(newX, l, "KMAC", s);
			//01001011 01001101 01000001 01000011
			//"11010010 10110010 10000010 11000010"
			
		}
		return kmac;
	}
	/**
	 * influenced by https://github.com/mjosaarinen/tiny
	 * @param c state of the data
	 * @param len of the output
	 */
	public static void shake128_init(sha3_ctx_t c, int len) {
		sha3_init(c, len);
	}
	/**
	 * influenced by https://github.com/mjosaarinen/tiny_sha3
	 * @param c state of the data 
	 * @param len of the output
	 */
	public static void shake256_init(sha3_ctx_t c, int len) {
		sha3_init(c, len);
	}
	/**
	 * influenced by https://github.com/mjosaarinen/tiny_sha3 
	 * @param theInfo state of the data currently
	 */
	public static void shake_xof(sha3_ctx_t theInfo) {
		byte[] b = theInfo.getB();
		byte temp = b[theInfo.getPT()];
		long hex = 0x04;
		temp ^= hex;
		b[theInfo.getPT()] = (byte) temp;
		hex = 0x80;
		//System.out.println("value of theInfo.getRsize()-1" + (theInfo.getRsize()-1));
		temp = b[theInfo.getRsize() - 1];
		temp ^= hex;
		
		b[theInfo.getRsize()-1] = temp;
		//System.out.println("the value of b in shake_xof" + Arrays.toString(b));
		theInfo.updateB(b);
		long[] q = convertByteArrayToArray(b);
		sha3_keccakf(q);
		b = convertLongArrayToByte(q);
		theInfo.updateB(b);
		theInfo.updateQ(q);
		theInfo.setPt(0);
		
		
	}
	/**
	 * influenced by https://github.com/mjosaarinen/tiny_sha3 
	 * @param theInfo state of the data currently
	 * @param out the output array
	 * @param len length of input
	 */
	public static byte[] shakeout(sha3_ctx_t theInfo, byte[] out, int len) {
		int j = theInfo.getPT();
		long[] q = theInfo.getQ();
		byte[] b = theInfo.getB();
		for(int i = 0; i < len; i++) {
			if(j >= theInfo.getRsize()) {
				sha3_keccakf(q);
				
				j = 0;
				
				theInfo.updateQ(q);
				b = convertLongArrayToByte(q);
				theInfo.updateB(b);
				
			}
			out[i] = b[j++];
		}
		theInfo.setPt(j);
		return out;
	}
	
	/**
	 * customizable SHAKE function
	 * @param x bitstring main input
	 * @param l length of output in bits
	 * @param n function name bit string
	 * @param s customization bit string
	 * @return
	 */
	public static byte[] cshake256(byte[] x, int l, String n, String s) {
	
		byte[] cshake = null;
		if(n == "" && s == "") {
			sha3_ctx_t sha = new sha3_ctx_t();
			shake256_init(sha, l);
			byte[] buf = new byte[64];
			if(l > 0) {
				for(int d = 0; d < 20; d++) {
				buf[d] = (byte) 0xA3;
				}
				for(int i = 0; i < 200; i+= 20) {
					sha3_update(sha, l, x);
				}
			}
			shake_xof(sha);
			for(int j = 0; j < 512; j+= 32) {
				buf = shakeout(sha, buf, l);
			}
			cshake = Arrays.copyOf(buf, l);
		} else {
			byte[] md = new byte[l];
			sha3_ctx_t sha = new sha3_ctx_t();
			byte[] nEncode = encode_string(n);
			byte[] sEncode = encode_string(s);
			int nLen = nEncode.length;
			int sLen = sEncode.length;

//			System.out.println("the encoded string of n is " + Arrays.toString(nEncode));
//			System.out.println("the encoded string of s is " + Arrays.toString(sEncode));
			byte[] ns = new byte[nLen+sLen];
			System.arraycopy(nEncode, 0, ns, 0, nLen);
			System.arraycopy(sEncode, 0, ns, nLen, sLen);
			//System.out.println("the encoded string of ns is " + Arrays.toString(ns));
			ns = bytepad(ns, 136);
			//System.out.println("the encoded string of ns after byte pad is " + Arrays.toString(ns));
			int nsLen = ns.length;
			int xLen = x.length;
		
			//xT = xT.shiftRight(2);
			//System.out.println("x currently is " + Arrays.toString(x));
			byte[] nsx = new byte[nsLen + xLen];
			System.arraycopy(ns, 0, nsx, 0, nsLen);
			System.arraycopy(x, 0, nsx, nsLen, xLen);
			//System.out.println("nsx is currently after adding x" + Arrays.toString(ns));
			
			//BigInteger nsxInt = new BigInteger(nsx);
			//nsxInt = nsxInt.shiftLeft(-2);
			//nsx = nsxInt.toByteArray();
		
			sha3_init(sha, 32);
			sha3_update(sha, nsx.length, nsx);
			
			md = sha.getB();
		
			shake_xof(sha);
//			nsxInt = new BigInteger(md);
			//nsxInt = nsxInt.shiftLeft(2);
			//nsx = nsxInt.toByteArray();
			md = sha.getB();
			
			//System.out.println("value of shab is " + Arrays.toString(sha.getB()) + " the length is " + sha.getB().length);
			//System.out.println("value of nsx is " + Arrays.toString(md) + " the length is " + md.length);
			String hashCode = "";
			for(int i = 0; i < l; i++ ) {
				String est = Integer.toHexString(Byte.toUnsignedInt(md[i]));
				if(est.length() < 2) {
					String zero = "0";
					est = zero.concat(est);
				}
				hashCode = hashCode.concat(est);
			}
			//System.out.println(hashCode);
			md = Arrays.copyOf(md, l);
			cshake = md;

		}
		return cshake;
	}
	/**
	 * Converts a byte array into a hex string
	 * @param theVals the byte array to be converted
	 * @return byte array as a hex string
	 */
	public static String getHash(byte[] theVals) {
		String hashCode = "";
		for(int i = 0; i < theVals.length; i++ ) {
			String est = Integer.toHexString(Byte.toUnsignedInt(theVals[i]));
			if(est.length() < 2) {
				String zero = "0";
				est = zero.concat(est);
			}
			hashCode = hashCode.concat(est);
		}
		return hashCode;
	}
	
	/**
	 * calculates message Authentication
	 * @param pw the password the message is being encoded under
	 * @param m the message
	 * @return the encoded message
	 */
	public static byte[] mAuthentication(byte[] pw, byte[] m) {
		byte[] t = kmacxof256(pw, m, 512, "T");
		return t;
	}
	/**
	 * encrypts a byte array under another byte array
	 * @param data the data that is to be encrypted
	 * @param pw the password represented in byte array form to encode the data under
	 * @return the encoded Cryptogram
	 */
	public static Cryptogram encryptByteArray(byte[] data, byte[] pw) {
		SecureRandom r = new SecureRandom();
		int z = r.nextInt(513);
		int pwLen = pw.length;
//		System.out.println("encryption z is" + z);
//		System.out.println("en pw is " + Arrays.toString(pw));
		BigInteger zBig = BigInteger.valueOf(z);
		byte[] zBytes = zBig.toByteArray();
		int zLen = zBytes.length;
		byte[] zpw = new byte[pwLen + zLen];
		System.arraycopy(zBytes, 0, zpw, 0, zLen);
		System.arraycopy(pw, 0, zpw, zLen, pwLen);
		String em = "";
		byte[] empty = em.getBytes();
		byte[] keka = kmacxof256(zpw, empty, 128, "S");
//		System.out.println("the value of keka in encrypt is" + Arrays.toString(keka));
		int half = keka.length/2;
		byte[] ke = Arrays.copyOfRange(keka, 0, half);
		byte[] ka = Arrays.copyOfRange(keka, half, keka.length);
//		System.out.println("the value of ke in encrypt is" + Arrays.toString(ke));
//		System.out.println("the value of ka in encrypt is" + Arrays.toString(ka));
//		System.out.println("the length of data in encrypt is " + data.length);
		ke = kmacxof256(ke, empty, data.length, "SKE");
		BigInteger dataBig = new BigInteger(data);
		BigInteger keBig = new BigInteger(ke);
		BigInteger c = dataBig.xor(keBig);
		byte[] cBytes = c.toByteArray();
		byte t[] = kmacxof256(ka, data, 64, "SKA");
		Cryptogram cCrypto = new Cryptogram(z, cBytes, t);
		return cCrypto;
	}
	/**
	 * decodes a given cryptogram under a byte array
	 * @param pw the password in byte array form
	 * @param theC the cryptogram to be decoded
	 * @return the decoded message in byte array form
	 */
	public static byte[] decryptByteArray(byte[] pw, Cryptogram theC) {
		int pwLen = pw.length;
		byte[] dCrypt = null;
		BigInteger zBig = BigInteger.valueOf(theC.getZ());
		//System.out.println("decryption z is" + zBig);
		//System.out.println("de pw is " + Arrays.toString(pw));
		byte[] zBytes = zBig.toByteArray();
		int zLen = zBytes.length;
		byte[] zpw = new byte[pwLen + zLen];
		System.arraycopy(zBytes, 0, zpw, 0, zLen);
		System.arraycopy(pw, 0, zpw, zLen, pwLen);
		String em = "";
		byte[] empty = em.getBytes();
		byte[] keka = kmacxof256(zpw, empty, 128, "S");
		//System.out.println("the value of keka in decrypt is" + Arrays.toString(keka));
		int half = keka.length/2;
		byte[] ke = Arrays.copyOfRange(keka, 0, half);
		byte[] c = theC.getC();
		byte[] t = theC.getT();
		int cLen = c.length;
		byte[] ka = Arrays.copyOfRange(keka, half, keka.length);
		ke = kmacxof256(ke, empty, cLen, "SKE");
		BigInteger dataBig = new BigInteger(c);
		BigInteger keBig = new BigInteger(ke);
		BigInteger cBig = dataBig.xor(keBig);
		byte[] mBytes = cBig.toByteArray();
		//System.out.println("the value of me is" + Arrays.toString(mBytes));
		if(mBytes.length < cLen) {
			int diff = theC.getC().length - mBytes.length;
			//System.out.println("the difference in length is " + diff);
			byte[] diffBytes = new byte[diff];
			for(int i = 0; i < diffBytes.length;i++) {
				diffBytes[i] = 0;
				
			}
			byte[] newM = new byte[cLen];
			System.arraycopy(diffBytes, 0, newM, 0, diff);
			System.arraycopy(mBytes, 0, newM, diff, mBytes.length);
			mBytes = newM;
			//System.out.println("newM is " + Arrays.toString(mBytes));
		}
		byte tprime[] = kmacxof256(ka, mBytes, 64, "SKA");
		System.out.println("t is equal to" + Arrays.toString(t));
		System.out.println("tprime is equal to" + Arrays.toString(tprime));
		if(Arrays.equals(tprime, t)) {
			System.out.println("this worked");
			dCrypt = mBytes;
		} else {
			System.out.println("this did not work");
			dCrypt = c;
		}


		return dCrypt;
	}
	//needs changes
	/**
	 * Generates a keyPair using Elliptic Points
	 * @param pw the password that will be used to generate key pairs
	 * @return the key pair for later use
	 */
	public static keyPair genKeyPair(byte[] pw) {
//		System.out.println("_________________________");
//		System.out.println("KEY");
		String em = "";
		byte[] empty = em.getBytes();
		byte[] s = kmacxof256(pw, empty, 64, "K");
		byte[] buf = byteToBigInt(s);
//		System.out.println("the value of s is " + Arrays.toString(s));
		BigInteger sBig = new BigInteger(buf);
		sBig = sBig.multiply(BigInteger.valueOf(4));
//		System.out.println("the value of sBig is " + sBig);
		EllipticPoint g = EllipticPoint.getG();

		g.multiPointWithInteger(sBig);
		keyPair k = new keyPair(sBig, g);
//		System.out.println("_________________________");
		return k;
		
	}
	/**
	 * 
	 * 
	 * encodes byte array using a key pair
	 * @param data the byte array that is to be encoded
	 * @param pw the password in key pair form
	 * @return returns an encrypted KGram(Key CryptoGram)
	 */
	public static KGram encryptByteArrayWithKey(byte[] data, keyPair pw) {

		SecureRandom r = new SecureRandom();
		//causes issues with decoding
		int k = r.nextInt(513);
		//int k = 0;
		k *= 4;
//		System.out.println("k value is " + k);
		EllipticPoint V = pw.getPublic();
		V.multiPointWithInteger(BigInteger.valueOf(k));
		EllipticPoint W = 	V;
//		System.out.println("W is gx" + W.getX() + " and gy is" + W.getY());
		EllipticPoint G = EllipticPoint.getG();
//		System.out.println("G is gx" + G.getX() + " and gy is" + G.getY());
		G.multiPointWithInteger(BigInteger.valueOf(k));
		EllipticPoint Z = G;
		//byte wXBytes[] = BigIntToByteArray(W.getX());
		byte wXBytes[] = W.getX().toByteArray();
//		System.out.println("encryption z is" + z);
//		System.out.println("en pw is " + Arrays.toString(pw));

		String em = "";
		byte[] empty = em.getBytes();
		byte[] keka = kmacxof256(wXBytes, empty, 128, "P");
//		System.out.println("the value of keka in encrypt is" + Arrays.toString(keka));
		int half = keka.length/2;
		byte[] ke = Arrays.copyOfRange(keka, 0, half);
		byte[] ka = Arrays.copyOfRange(keka, half, keka.length);
//		System.out.println("the value of ke in encrypt is" + Arrays.toString(ke));
//		System.out.println("the value of ka in encrypt is" + Arrays.toString(ka));
//		System.out.println("the length of data in encrypt is " + data.length);
		ke = kmacxof256(ke, empty, data.length, "PKE");
		BigInteger dataBig = new BigInteger(data);
		BigInteger keBig = new BigInteger(ke);
		BigInteger c = dataBig.xor(keBig);
		//byte[] cBytes = BigIntToByteArray(c);
		byte[] cBytes = c.toByteArray();
		byte t[] = kmacxof256(ka, data, 64, "PKA");
		//System.out.println("Zx is " + Z.getX());
		//System.out.println("Zy is " + Z.getY());
		KGram kCrypto = new KGram(Z, cBytes, t);

		return kCrypto;
	}
	/**
	 * 
	 * Decodes a given KGram under a byte array
	 * @param pw the byte array form of the password
	 * @param theC the KGram to be decoded
	 * @return the decoded message
	 */
	public static byte[] decryptByteArrayWithKey(byte[] pw, KGram theC) {
//		System.out.println("_________________________");
//		System.out.println("DECODE");
		byte[] dCrypt = null;
		System.out.println("the passward is" + Arrays.toString(pw));
		String em = "";
		byte[] empty = em.getBytes();
		byte[] s = kmacxof256(pw, empty, 64, "K");
//		System.out.println("the value of s is " + Arrays.toString(s));
		BigInteger sBig = new BigInteger(s);
		sBig = sBig.multiply(BigInteger.valueOf(4));
//		System.out.println("the value of sBig is " + sBig);
		EllipticPoint Z = theC.getZ();
		System.out.println("Z x before is" + Z.getX() + "Z y before is " + Z.getY());
		Z.multiPointWithInteger(sBig);
		EllipticPoint W = Z;
//		System.out.println("Z x after is" + W.getX() + "Z y after is " + W.getY());
		//byte[] wXBytes = BigIntToByteArray(W.getX());
		byte[] wXBytes = W.getX().toByteArray();
		byte[] keka = kmacxof256(wXBytes, empty, 128, "P");
		//System.out.println("the value of keka in decrypt is" + Arrays.toString(keka));
		int half = keka.length/2;
		byte[] ke = Arrays.copyOfRange(keka, 0, half);
		byte[] c = theC.getC();
		System.out.println("c in decrypt is" + Arrays.toString(c));
		byte[] t = theC.getT();
		System.out.println("t in decrypt is" + Arrays.toString(t));
		int cLen = c.length;
		byte[] ka = Arrays.copyOfRange(keka, half, keka.length);
		ke = kmacxof256(ke, empty, cLen, "PKE");
		BigInteger dataBig = new BigInteger(c);
		BigInteger keBig = new BigInteger(ke);
		BigInteger cBig = dataBig.xor(keBig);
		//byte[] mBytes = BigIntToByteArray(cBig);
		byte[] mBytes = cBig.toByteArray();
		if(mBytes.length < cLen) {
			int diff = theC.getC().length - mBytes.length;
			//System.out.println("the difference in length is " + diff);
			byte[] diffBytes = new byte[diff];
			for(int i = 0; i < diffBytes.length;i++) {
				diffBytes[i] = 0;
				
			}
			byte[] newM = new byte[cLen];
			System.arraycopy(diffBytes, 0, newM, 0, diff);
			System.arraycopy(mBytes, 0, newM, diff, mBytes.length);
			mBytes = newM;
			//System.out.println("newM is " + Arrays.toString(mBytes));
		}
		System.out.println("the value of m is" + Arrays.toString(mBytes));
//		
		byte tprime[] = kmacxof256(ka, mBytes, 64, "PKA");
//		BigInteger tprimeBig = new BigInteger(tprime);
//		System.out.println("t is equal to" + Arrays.toString(t));
//		System.out.println("tprime is equal to" + Arrays.toString(tprime));
//		System.out.println("tprimeBig is equal to" + tprimeBig);
		if(Arrays.equals(tprime, t)) {
			System.out.println("this worked");
			dCrypt = mBytes;
		} else {
			System.out.println("this did not work");
			dCrypt = c;
		}

//		System.out.println("_________________________");
		return dCrypt;
	}
	/**
	 * @param pw
	 * @return signature of 
	 */
	/**
	 * generates a digital signature
	 * @deprecated use generateSign method instead
	 * @param m the message to be signed
	 * @param pw the byte array form of the password
	 * @return signature of m
	 */
	static public Signature genSignature(byte[] m, byte[] pw) {
		//step 1
		String em = "";
		byte[] empty = em.getBytes();
		byte[] s = kmacxof256(pw, empty, 64,"K");
		byte[] sBuf = byteToBigInt(s);
		BigInteger sBig = new BigInteger(sBuf);
		//step 2
		sBig = sBig.multiply(BigInteger.valueOf(4));
		byte[] newS = sBig.toByteArray();
		//step 3
		byte[] k = kmacxof256(newS, m, 64, "N");
		byte[] kBuf = byteToBigInt(k);
		
		//step 4
		BigInteger kBig = new BigInteger(kBuf);
		kBig = kBig.multiply(BigInteger.valueOf(4));
		
		
		// step 5
		EllipticPoint G = new EllipticPoint(BigInteger.valueOf(4), false);
		G.multiPointWithInteger(kBig);
		EllipticPoint U = G;
		
		
		//System.out.println("Ux as an BigINt is" + U.getX());
		
		//step 6
		byte[] Ux = U.getX().toByteArray();
		byte[] h = kmacxof256(Ux, m, 64, "T");
		//System.out.println("hBefore is " + Arrays.toString(h));
		byte[] hBuf = byteToBigInt(h);
		//System.out.println("hBuf is " + Arrays.toString(hBuf));
		//System.out.println("the value of UX before is " + Arrays.toString(U.getX().toByteArray()));
		BigInteger hBig = new BigInteger(hBuf);
		//System.out.println("hBig is" + hBig);
		
		//step 7
		BigInteger z = (kBig.subtract((hBig.multiply(sBig)))).mod(U.genR());
		byte[] zBytes = z.toByteArray();
		
		//step 8
		Signature sig = new Signature(hBuf, zBytes);
		return sig;
	}
	/**
	 * ISSUES WITH verifying signature
	 * verifies signature 
	 * @deprecated use VerifySign method instead
	 * @param sig signature to be verified
	 * @param V the public key
	 * @param m the message
	 * @return the message
	 */
	static public boolean VerSignature(Signature sig, EllipticPoint V, byte[] m) {
		boolean state = false;
		EllipticPoint G = EllipticPoint.getG();
		//System.out.println("Gx before is " + G.getX());
		//System.out.println("Gy before is " + G.getY());
		byte[] sigZ = byteToBigInt(sig.getZ());
		BigInteger zBig = new BigInteger(sigZ);
		
		//Step 1
		G.multiPointWithInteger(zBig);
		//System.out.println("Gx after is " + G.getX());
		//System.out.println("Gy after is " + G.getY());
		
		//step 2
		byte[] sigH = sig.getH();
		BigInteger hBig = new BigInteger(sigH);
		V.multiPointWithInteger(hBig);
		
		//step 3
		EllipticPoint U = G.sumPoints(G, V);
		//System.out.println("Ux as an BigINt is" + U.getX());
		
		
		//step 4
		byte[] Ux = U.getX().toByteArray();
				//.toByteArray();
//		System.out.println("U is" + Arrays.toString(Ux));
//		System.out.println("U is" + new BigInteger(sigH));
//		System.out.println("h is" + Arrays.toString(sigH));
//		System.out.println("z is" + Arrays.toString(sigZ));
		byte[] testArray = kmacxof256(Ux, m, 64, "T");
		//System.out.println("testArray is" + new BigInteger(testArray));
		if(Arrays.equals(sig.getH(), testArray)) {
			state = true;
			//System.out.println("worked");
		} else {
			state = false;
			//System.out.println("did not worked");
		}
		return state;
	}
	/**
	 * helper method to convert bigIntToByteArray
	 * @param x the bigInteger to convert
	 * @return the byte form of bigIntger with an added 0 in the lead
	 */
	public static byte[] BigIntToByteArray(BigInteger x) {
		byte[] xBytes = x.toByteArray();
		byte[] zero = {0};
		byte[] newArray = new byte[xBytes.length+ zero.length];
		System.arraycopy(zero, 0, newArray, 0, zero.length);
		System.arraycopy(xBytes, 0, newArray, zero.length, xBytes.length);
		return newArray;
	}
	public static byte[] byteToBigInt(byte[] m) {
		byte[] buf = new byte[m.length+1];
		buf[0] = (byte) 0;
		for(int i = 0; i < m.length; i++) {
			buf[i+1] = m[i];
		}
		return buf;
	}
	/**
	 * right encodes a big integer
	 * @param x the big integer being encoded
	 * @return the byte representation of right encoding
	 */
	private static byte[] right_encode(BigInteger x) {
	
		
		// min number n  so 2^8n > x

		int n = x.toByteArray().length;
		
		if(n < 1) {
			 n = 1;
		} 
		
		BigInteger len = BigInteger.valueOf(n);
		byte[] lenB = len.toByteArray();
		byte[] xBits = x.toByteArray();
		int m = lenB.length;
		byte[] rEncode = new byte[n+m];
		System.arraycopy(xBits, 0, rEncode, 0, n);
		System.arraycopy(lenB, 0, rEncode, n, m);

		
		
		return rEncode;
	}
	/**
	 * left encodes a big integer
	 * @param x the big integer being encoded
	 * @return the byte representation of left encoding
	 */
	private static byte[] left_encode(BigInteger x) {
				
		int n = x.toByteArray().length;
				
		if(n < 1) {
				n = 1;
		} 
				
			BigInteger len = BigInteger.valueOf(n);
			byte[] lenB = len.toByteArray();
			byte[] xBits = x.toByteArray();
			int m = lenB.length;
			byte[] lEncode = new byte[n+m];
			System.arraycopy(lenB, 0, lEncode, 0, m);
			System.arraycopy(xBits, 0, lEncode, m, n);

				return lEncode;
			}
	/**
	 * 
	* @param S the string being encoded 
	* @return the string that is encoded with its length
	*/
	private static byte[] encode_string(String S) {
		byte[] theString = S.getBytes();
		int n = theString.length;

		BigInteger len = BigInteger.valueOf(n*8);
		 
		byte[] lenB = left_encode(len);
		int m = lenB.length;
		byte[] encode = new byte[n+m];
		System.arraycopy(lenB, 0, encode, 0, m);
		System.arraycopy(theString, 0, encode, m, n);
		return encode;
	}
	/**
	 * pads the length of each bitstring
	 * @param theBytes that were converted from a string
	 * @param theNum length that byte array shall be a multiple of
	 * @return
	 */
	private static byte[] bytepad(byte[] theBytes, int theNum) {
		byte[] nBytes = theBytes;
		byte[] theNumB;
		Integer theNumVal = theNum;
		int n = theBytes.length;
		if(theNum > 0) {
			
			
			if( theNum < 256 && theNum > 127) {
				byte nVal = theNumVal.byteValue();
				theNumB = left_encode(BigInteger.valueOf(nVal));
			} else {
				theNumB = left_encode(BigInteger.valueOf(theNum));
			}
		
			int m = theNumB.length;
			nBytes = new byte[n + m];
			System.arraycopy(theNumB, 0, nBytes, 0, m);
			System.arraycopy(theBytes, 0, nBytes, m, n);
			
			List<Byte> fBytes = new ArrayList<Byte>();
			for(byte b : nBytes) {
				fBytes.add(b);
			}
			while(((fBytes.size()) % theNum) != 0) {
				fBytes.add((byte) 0);
			}
			nBytes = new byte[fBytes.size()];
			for(int i = 0; i < nBytes.length; i++) {
				nBytes[i] = fBytes.get(i);
			}
			
		}
		
		
		return nBytes;
	}
	/**
	 * converts a long array to byte to mimic union in c
	 * @param theVal the long array to be converted
	 * @return byte array represention of the long array
	 */
	private static byte[] convertLongArrayToByte(long[] theVal) {
		int len = theVal.length*8;
		byte[] byteVals = new byte[len];
		for(int i = 0; i < theVal.length; i++) {
			
			BigInteger temp = BigInteger.valueOf(Long.parseUnsignedLong(Long.toUnsignedString(theVal[i])));
			

			byte[] t = temp.toByteArray();
			int ledZero = 8 - t.length;
			int counter = 0;
				for(int j = 8*i; j < (8*i)+8; j++) {
					if(ledZero > 0 && t.length != 8) {
						byteVals[j] = 0;
//						System.out.println("hiit");
						ledZero--;
					}else {
						byteVals[j] = t[counter];
						counter++;
				}
			}
			
		}
		return byteVals;
	}
	/**
	 * converts byte array into a long array to mimic union in c
	 * @param theVal the byte array to convert
	 * @return the long array representation of the byte array
	 */
	private static long[] convertByteArrayToArray(byte[] theVal) {
		int len = theVal.length/8;
		long[] longVals = new long[len];
		for(int i = 0; i < longVals.length; i++) {
			byte[] bits = Arrays.copyOfRange(theVal, 8*i, (8*i)+8);
//			System.out.println("the bits at " + i + " are" + Arrays.toString(bits));
			BigInteger ex = new BigInteger(bits);
			
			longVals[i] = ex.longValue();
		}
		return longVals;
	}
}