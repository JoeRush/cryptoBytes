package Application;

import java.math.BigInteger;

/**
 * @author Joseph Rushford
 * @author Matthew Molina
 */

public class PseudoUnion {
	private long myLong;
	private byte[] myBits;
	public PseudoUnion() {
		myLong = 0;
	    myBits = new byte[8];
	}
	public long getVal() {
		return myLong;
	}
	public byte[] getBits() {
		return myBits;
	}
	public void changeByteAt(int i, byte newVal) {
		
		if(i < 8) {
			myBits[i] = newVal;
			BigInteger temp = new BigInteger(myBits);
			myLong = temp.longValue();
		}
	}
	public void changeLong(long newVal) {

		BigInteger temp = BigInteger.valueOf(newVal);
		byte[] ar = temp.toByteArray();
		

		if(ar.length != 8) {
			int pointer = ar.length - 1;
	
			for(int i = 7; i >= 0; i--) {
				if(pointer >= 0) {
					myBits[i] = ar[pointer];
				
					pointer--;
				}
			}
		} else {
			for(int i = 7; i >= 0; i--) {
				myBits[i] = ar[i];
			}
		}
		myLong = newVal;
	}
	
}
