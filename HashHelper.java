import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class HashHelper {
	
	public static final String HMAC_SHA512 = "HmacSHA512";

	public static String getHmacSHA512(String str, String secret) {
		Mac macInst = null;
		String result = "";
		
		try {
			macInst = Mac.getInstance(HMAC_SHA512);
			macInst.init(new SecretKeySpec(secret.getBytes("UTF-8"), HMAC_SHA512));
			
			result = DatatypeConverter.printHexBinary((macInst.doFinal(str.getBytes("UTF-8")))).toLowerCase();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (IllegalStateException e) {
			e.printStackTrace();
		}
		
		return result;
	}
}
