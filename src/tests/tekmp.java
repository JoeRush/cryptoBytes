package tests;

import Application.sha3;

public class tekmp {
	public static void main(String[] args) {
//	byte test = -97;
//	String ds = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F 40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F 60 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E 7F 80 81 82 83 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F 90 91 92 93 94 95 96 97 98 99 9A 9B 9C 9D 9E 9F A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF C0 C1 C2 C3 C4 C5 C6 C7";  
//	 
//	String ss = "00 01 02 03";
////	System.out.println("the value of test unsigned is " + Byte.toUnsignedInt(test));
////	String email = "Email Signature";
////	System.out.println("email is " +email);
////	System.out.println("the number of bytes is " + email.getBytes().length + " which is " + email.getBytes().length*8);
////	System.out.println("email as bytes is" + Arrays.toString(email.getBytes()));
//	String kmac = "KMAC";
//	System.out.println("KMAC is " + kmac);
//	System.out.println("the number of bytes is " + kmac.getBytes().length + " which is " + kmac.getBytes().length*8);
//	System.out.println("kmac as bytes is" + Arrays.toString(kmac.getBytes()));
//	String arr[] = ss.split("\\s+");
//	byte barr[] = new byte[arr.length];
//	String testing = "Test";
//	byte[] testBytes = testing.getBytes();
//	String empt = "";
//	byte[] em = empt.getBytes();
//
	
//	String n = "";
////	Integer sixteen = 168;
////	Byte sx = sixteen.byteValue();
////	System.out.println("the byte value of 168 is " + sx);
////	BigInteger eight = BigInteger.valueOf(-88);
////	byte[] eByte = eight.toByteArray();
////	System.out.println("the value of eight is " + Arrays.toString(eByte));
////	eight = new BigInteger(eByte);
////	System.out.println("the value of eight is now " + eight);
//	String s = "Email Signature";
//	for(int i = 0; i < barr.length;i++) {
//		int in = Integer.parseInt(arr[i], 16  );
//		BigInteger big = BigInteger.valueOf(in);
//		
//		byte k = big.byteValue();
//		//byte k = (byte)Byte.parseByte(arr[i], 16);
//
//		barr[i] = k;
//	}
//
//   // "2F1A5F7159E34EA19CDDC70EBF9B81F1A66DB40615D7EAD3CC1F1B954D82A3AF"
//	
//	
//	BigInteger g = BigInteger.valueOf(test);
//	Cryptogram ctest = sha3.encryptByteArray(barr, testBytes);
		byte md[] = new byte[64];

		int lT = 64;
		byte[] x = new byte[4];
		x[0] = 0;
		x[1] = 1;
		x[2] = 2;
		x[3] = 3;
	byte[] sd = new byte[0];
	md = sha3.kmacxof256(sd, x, lT, "Email Signature");
//	System.out.println("the value within barr is" + Arrays.toString(barr));
//	System.out.println("the value of c is " + Arrays.toString(ctest.getC()) + " and the length is " + ctest.getC().length);
//	byte[] mess = sha3.decryptByteArray(testBytes, ctest);
//	System.out.println("mess is " + Arrays.toString(mess));
//	//System.out.println("the value after kmac is " + Arrays.toString(md) + "and the array length is" + md.length);
//	
//
	}
}
