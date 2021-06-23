package Application;

import java.math.BigInteger;
/**
 * Creates Elliptic Curve Points that can be used later
 * @author Joseph Rushford
 * @author Matthew Molina
 *
 */
public class EllipticPoint implements Comparable<EllipticPoint>{
	final private static BigInteger mersennePrime = 
			(BigInteger.valueOf(2).pow(521)).subtract(BigInteger.valueOf(1));
    final private static BigInteger d = BigInteger.valueOf(Long.parseLong("-376014"));
    
	private BigInteger myX;
	private BigInteger myY;
	/**
	 * constructor for neutral point
	 */
	public EllipticPoint(){
		myX = BigInteger.valueOf(0);
		myY = BigInteger.valueOf(1);
	}
	/**
	 * constructor give an x and y
	 * @param x coordinate of the point
	 * @param y coordinate of the point
	 */
	public EllipticPoint(BigInteger x, BigInteger y){
		myX = x;
		myY = y;
	}
	/**
	 * constructor given an x and the y coordinate's less significant bit
	 * @param x coordinate of the point
	 * @param y the less significant bit
	 */
	public EllipticPoint(BigInteger x, boolean y){
		myX = x;
		BigInteger top = BigInteger.ONE.subtract(x.pow(2));
		top = top.mod(mersennePrime);
		BigInteger newd = d.multiply(BigInteger.valueOf(-1));
		newd = newd.multiply(x.pow(2));
		
		BigInteger bot = BigInteger.ONE.add(newd);
		bot = (bot.modInverse(mersennePrime)).mod(mersennePrime);
		BigInteger newY = top.multiply(bot);
		newY = sqrt(newY, mersennePrime, y);
		myY = newY;
		//myY = BigInteger.valueOf(6);
	}
	/**
	 * the x coordinate of the point
	 * @return the x coordinate of the point
	 */
	public BigInteger getX() {
		return myX;
		
	}
	/**
	 * gets the y coordinate of the point
	 * @return y coordinate of hte point
	 */
	public BigInteger getY() {
		return myY;
	}
	/**
	 * gets the G point of the Elliptic Curve
	 * @return G point
	 */
	public static EllipticPoint getG() {
		EllipticPoint  g = new EllipticPoint(BigInteger.valueOf(4), false);
		return g;
	}
	/**
	 * PROBABLY WHERE THE PROBLEM IS WITH PART 4 AND 5
	 * sums two points one the Elliptic Curve
	 * @param one the first point to be sumed
	 * @param two the second point to be summed
	 * @return the summed point
	 */
	public EllipticPoint sumPoints(EllipticPoint one, EllipticPoint two) {

		BigInteger x1 = one.getX().multiply(two.getY());
		BigInteger x2 = one.getY().multiply(two.getX());
		BigInteger x2add = x1.add(x2);
		BigInteger xinverse = x2add.mod(mersennePrime);
		BigInteger b1 = BigInteger.ONE;
		BigInteger b2 = d.multiply(one.getX());
		BigInteger b3 = b2.multiply(two.getX());
		BigInteger b4 = b3.multiply(one.getY());
		BigInteger b5 = b4.multiply(two.getY());
		BigInteger bfinal = b1.add(b5);
		BigInteger binverse = bfinal.modInverse(mersennePrime);
		binverse = binverse.mod(mersennePrime);
		BigInteger xFinal = (xinverse.multiply(binverse)).mod(mersennePrime);
				//.modInverse(mersennePrime);
		//System.out.println("xFinal is " + xFinal);
		
		BigInteger y1 = one.getY().multiply(two.getY());
		BigInteger y2 = one.getX().multiply(two.getX());
		BigInteger yminus = y1.subtract(y2);
		BigInteger yinverse = yminus.mod(mersennePrime);
		BigInteger by1 = BigInteger.ONE;
		BigInteger by2 = d.multiply(one.getX());
		BigInteger by3 = by2.multiply(two.getX());
		BigInteger by4 = by3.multiply(one.getY());
		BigInteger by5 = by4.multiply(two.getY());
		BigInteger byfinal = by1.subtract(by5);
		BigInteger byinverse = byfinal.modInverse(mersennePrime);
		byinverse = byinverse.mod(mersennePrime);
		BigInteger yFinal = (yinverse.multiply(byinverse)).mod(mersennePrime);
				//.modInverse(mersennePrime);
		//System.out.println("yFinal is " + yFinal);
		
		EllipticPoint newPoint = new EllipticPoint(xFinal, yFinal);
		
		
		return newPoint;
	}
	/**
	 * gets teh oppositePoint of the current point
	 * @return the oppositePoint
	 */
	public EllipticPoint oppositePoint() {
		
		BigInteger newX = myX.negate().mod(mersennePrime);
		
		EllipticPoint opposite = new EllipticPoint(newX, myY);
		return opposite;
		
	}
	/**
	 * multiplies the point by a scalar value
	 * @param x the scalar value
	 */
	public void multiPointWithInteger(BigInteger x) {
		EllipticPoint Y = new EllipticPoint(myX, myY);
		//System.out.println("Y is " + Y.getX() + " " + Y.getY());
		int bits = x.bitLength();

		//System.out.println("x is " + x + "the bit count is " + bits);
		for( int i = bits-1; i >= 0; i--) {
			//System.out.println("i is " + i);
			Y = Y.sumPoints(Y, Y);
			//System.out.println(i);
			//Y.doublePoint();
			if(x.testBit(i)) {
				//System.out.println(i);
				Y = sumPoints(Y , this);
			} 
		}
		myX = Y.getX();
		myY = Y.getY();
	}
	/**
	 * gets the number used to calculate number of points
	 * @return the number used to calculate number of points
	 */
	public BigInteger genR() {
		String test = "0337554763258501705789107630418782636071904961214051226618635150085779108655765";
		BigInteger r = new BigInteger(test);
		
		BigInteger bigTwo = BigInteger.valueOf(2);
		bigTwo = bigTwo.pow(519);
		//System.out.println("bigTwo" + bigTwo);
		bigTwo = bigTwo.subtract(r);
		//System.out.println("bigTwo" + r);
		//System.out.println("bigTwo after r" + bigTwo);
		return bigTwo;
	
	}
	/**  * Compute a square root of v mod p with a specified  
	 * * least significant bit, if such a root exists.  
	 * *  * @param   v   the radicand.  
	 * * @param   p   the modulus (must satisfy p mod 4 = 3).  
	 * * @param   lsb desired least significant bit (true: 1, false: 0).  
	 * * @return  a square root r of v mod p with r mod 2 = 1 iff lsb = true  
	 *   *          if such a root exists, otherwise null.  */ 

	public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {     
		assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)     
		if (v.signum() == 0) {         
			return BigInteger.ZERO;     
		}     
		BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);     
		if (r.testBit(0) != lsb) {         
			r = p.subtract(r); // correct the lsb     
		}     
		return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null; 
	}
	/**
	 * comparable for points
	 */
	@Override
	public int compareTo(EllipticPoint o) {
		int same = -1;
		if(this.getX().compareTo(o.getX()) == 0 && this.getY().compareTo(o.getY()) == 0) {
			same = 0;
		}
		// TODO Auto-generated method stub
		return same;
	} 
	
	
}
