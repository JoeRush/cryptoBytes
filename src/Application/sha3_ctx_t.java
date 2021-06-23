package Application;


/**
 * the state of sha3 
 * @author Joseph Rushford
 * @author Matthew Molina
 *
 */
public class sha3_ctx_t {
	private int pt;
	private int rsize;
	private int mdlen;
	private long q[];
	private byte b[];
	
	/**
	 * constructor to set temp values
	 */
	public sha3_ctx_t() {
		pt = 0;
		rsize = 0;
		mdlen = 0;

		q = new long[25];
		b = new byte[200];
		
		

		
	}
	/**
	 * sets the output length
	 * @param mdlen2 the length of output
	 */
	public void setMdlen(int mdlen2) {
		mdlen = mdlen2;
		
	}
	/**
	 * sets the rsize
	 * @param i the value rsize is set to
	 */
	public void setRsize(int i) {
		rsize = i;
		
	}
	/**
	 * sets pt to value
	 * @param i the value pt is set to
	 */
	public void setPt(int i) {
		pt = i;
		
	}
	/**
	 * the long state of the data
	 * @return long array representing the data
	 */
	public long[] getQ() {
		return q;
	}
	/**
	 * the byte state of the data
	 * @return byte array representing the data
	 */
	public byte[] getB() {
		return b;
	}
	/**
	 * updates byte state of the data
	 * @param newB the new byte state of data
	 */
	public void updateB(byte[] newB) {
		b = newB;
	}
	/**
	 * udates long state of the data
	 * 
	 * @param newQ the new long state of data
	 */
	public void updateQ(long[] newQ) {
		q = newQ;
	}
	/**
	 * gets the pt value
	 * @return pt
	 */
	public int getPT() {
		
		return pt;
	}
	/**
	 * gets the rsize
	 * @return rsize
	 */
	public int getRsize() {
		return rsize;
	}
	/**
	 * gets the output length
	 * @return output length
	 */
	public int getMdlen() {
		
		return mdlen;
	}
}
