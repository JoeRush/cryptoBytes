/**
 * 
 */
package tests;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import Application.sha3;

/**
 * @author jr-99
 *
 */
public class Sha3tests extends sha3 {
	sha3 theSha;
	String[][] data;
	int failCount;
	int msg_length;
	long[] buf;
	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		theSha = new sha3();
		String[][] temp = {{
			 	 "",
	            "6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7"},
				{
	              "9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10",
	              "2F1A5F7159E34EA19CDDC70EBF9B81F1A66DB40615D7EAD3CC1F1B954D82A3AF"
				}, 
				{"E35780EB9799AD4C77535D4DDB683CF33EF367715327CF4C4A58ED9CBDCDD486"
				 + "F669F80189D549A9364FA82A51A52654EC721BB3AAB95DCEB4A86A6AFA93826D"
		         + "B923517E928F33E3FBA850D45660EF83B9876ACCAFA2A9987A254B137C6E140A"
		         + "21691E1069413848",
		         "D1C0FA85C8D183BEFF99AD9D752B263E286B477F79F0710B0103170173978133"
		         + "44B99DAF3BB7B1BC5E8D722BAC85943A"},
				{"3A3A819C48EFDE2AD914FBF00E18AB6BC4F14513AB27D0C178A188B61431E7F5" +
	            "623CB66B23346775D386B50E982C493ADBBFC54B9A3CD383382336A1A0B2150A" +
	            "15358F336D03AE18F666C7573D55C4FD181C29E6CCFDE63EA35F0ADF5885CFC0" +
	            "A3D84A2B2E4DD24496DB789E663170CEF74798AA1BBCD4574EA0BBA40489D764" +
	            "B2F83AADC66B148B4A0CD95246C127D5871C4F11418690A5DDF01246A0C80A43" +
	            "C70088B6183639DCFDA4125BD113A8F49EE23ED306FAAC576C3FB0C1E256671D" +
	            "817FC2534A52F5B439F72E424DE376F4C565CCA82307DD9EF76DA5B7C4EB7E08" +
	            "5172E328807C02D011FFBF33785378D79DC266F6A5BE6BB0E4A92ECEEBAEB1", 
	            "6E8B8BD195BDD560689AF2348BDC74AB7CD05ED8B9A57711E9BE71E9726FDA45" +
	            "91FEE12205EDACAF82FFBBAF16DFF9E702A708862080166C2FF6BA379BC7FFC2"}};
		data = temp;
		failCount = 0;
		msg_length = 0;
		buf = new long[64];

	}

	/**
	 * Test method for {@link Application.sha3#sha3_init(Application.sha3_ctx_t, int)}.
	 */
	@Test
	public final void testSha3_init() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link Application.sha3#sha3_update(Application.sha3_ctx_t, long, java.lang.String)}.
	 */
	@Test
	public final void testSha3_update() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link Application.sha3#sha3_final(long[], Application.sha3_ctx_t)}.
	 */
	@Test
	public final void testSha3_final() {
		fail("Not yet implemented");
	}

//	/**
//	 * Test method for {@link Application.sha3#sha3H(int, long, long[], java.lang.String)}.
//	 */
//	@Test
//	public final void testSha3H() {
//		String outcome = sha3H(data[0][0], data[0][0].length(), buf, data[0][1].length());
//		assertEquals(outcome, data[0][1]);
//		
//	}



	/**
	 * Test method for {@link Application.sha3#shake256_init(Application.sha3_ctx_t, int)}.
	 */
	@Test
	public final void testShake256_init() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link Application.sha3#kmacxof256(java.lang.String, java.lang.String, int, java.lang.String)}.
	 */
	@Test
	public final void testKmacxof256() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link Application.sha3#shake_xof(Application.sha3_ctx_t)}.
	 */
	@Test
	public final void testShake_xof() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link Application.sha3#shakeout(Application.sha3_ctx_t, long[], int)}.
	 */
	@Test
	public final void testShakeout() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link Application.sha3#cshake128(java.lang.String, int, java.lang.String, java.lang.String)}.
	 */
	@Test
	public final void testCshake128() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link Application.sha3#cshake256(java.lang.String, int, java.lang.String, java.lang.String)}.
	 */
	@Test
	public final void testCshake256() {
		fail("Not yet implemented");
	}

//	/**
//	 * Test method for {@link Application.sha3#right_encode(long)}.
//	 */
//	@Test
//	public final void testRight_encode() {
//		String s = "";
//		String encoded = sha3.right_encode(s.length());
//		System.out.println(encoded);
//		assertEquals(encoded, "0000000010000000");
//	}

	/**
	 * Test method for {@link Application.sha3#left_encode(long)}.
	 */
	@Test
	public final void testLeft_encode() {
		fail("Not yet implemented");
	}

//	/**
//	 * Test method for {@link Application.sha3#encode_string(java.lang.String)}.
//	 */
//	@Test
//	public final void testEncode_string() {
//		String s = "";
//		String encoded = sha3.encode_string(s);
//		System.out.println(encoded);
//		assertEquals(encoded, "1000000000000000");
//	}

	/**
	 * Test method for {@link Application.sha3#bytepad(java.lang.String, long)}.
	 */
	@Test
	public final void testBytepad() {
		fail("Not yet implemented");
	}

}
