import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;

import com.google.gson.JsonObject;

public class BTCE_API_Lib {
	public static final String API_KEY_PATTERN = "([A-Z|0-9]{8}-){4}[A-Z|0-9]{8}";
	public static final String API_SECRET_PATTERN = "[a-f|0-9]{64}";
	
	public static final String POST_METHOD = "method";
	public static final String POST_NONCE = "nonce";
	
	private static String BTCE_API_URL = "https://btc-e.com/tapi/";
	private static String BTCE_BASIC_URL = "https://btc-e.com/api/3/";
	
	private static int nonce = -1;
	
	/*
	 * URL should be changeable if BTC-E ever decides to modify it
	 */
	public static void setAPIUrl(String URL) {
		BTCE_API_URL = URL;
	}
	
	/*
	 * Same here but for the basic URL
	 */
	public static void setBasicUrl(String URL) {
		BTCE_BASIC_URL = URL;
	}

	public static boolean isValidAPIKey(String str) {
		return str.matches(BTCE_API_Lib.API_KEY_PATTERN);
	}
	
	public static boolean isValidSecret(String str) {
		return str.matches(BTCE_API_Lib.API_SECRET_PATTERN);
	}
	
	private static void log(String str) {
		System.out.println("[BTC-E API LIB] ".concat(str));
	}
	
	private static int getNonce() {
		/*
		 * "Non-secure" Random.class is sufficient
		 */
		return nonce == -1 ? (new Random()).nextInt(Integer.MAX_VALUE / 10) : ++nonce;
	}
	
	public static void setNonce(int val) {
		nonce = val;
	}
	
	public static void fixNonce(JsonObject obj) {
		setNonce(extractNonce(obj));
	}
	
	public static int extractNonce(JsonObject obj) {
		String errorStr = obj.get("error").getAsString();
		
		Pattern noncePattern = Pattern.compile("key:\\d*");
		Matcher matcher = noncePattern.matcher(errorStr);
		
		if(matcher.find()) {
			String match = matcher.group();
			log("Found pattern: \"".concat(match).concat("\" in string: \"").concat(errorStr).concat("\""));
			return Integer.parseInt(match.split(":")[1]);
		}
		
		log("Failed to find pattern in string: \"".concat(errorStr).concat("\""));
		
		return -1;
	}
	
	private String key = null;
	private String secret = null;
	
	public BTCE_API_Lib(String key, String secret) {
		this.key = key;
		this.secret = secret;
	}
	
	public JsonObject performBasicRequest(String method, NameValuePair optionalGetData) {
		JsonObject result = null;
		
		String URL = BTCE_BASIC_URL.concat(method);
		
		if(optionalGetData != null) {
			URL.concat("?").concat(optionalGetData.getName()).concat("=").concat(optionalGetData.getValue());
		}
		
		HttpClient client = HttpClients.createDefault();
		HttpGet get = new HttpGet(URL);
		
		try {
			HttpResponse response = client.execute(get);
			HttpEntity entity = response.getEntity();
			
			if(entity == null)
				throw new NullPointerException();
			
			result = JsonHelper.getAsJson(IOUtils.toString(entity.getContent(), "UTF-8"));
		} catch (Exception e) {
			log("Failed to perform POST request");
			e.printStackTrace();
			return null;
		}
		
		return result;
	}
	
	/*
	 * This function automatically adds the nonce parameter
	 */
	public JsonObject performAuthorizedRequest(ArrayList<NameValuePair> postData) {
		for(NameValuePair pair : postData) {
			if(pair.getName().equals("nonce")) {
				postData.remove(pair);
				break;
			}
		}
		
		postData.add(new BasicNameValuePair("nonce", String.valueOf(getNonce())));
		
		LinkedHashMap<String, String> headers = createHeaders(postData);
		
		return sendRequest(BTCE_API_URL, postData, headers);
	}
	
	private JsonObject sendRequest(String URL, ArrayList<NameValuePair> postData, LinkedHashMap<String, String> headers) {
		JsonObject result = null;
		
		HttpClient client = HttpClients.createDefault();
		HttpPost post = new HttpPost(URL);
		
		try {
			post.setEntity(new UrlEncodedFormEntity(postData, "UTF-8"));
			
			for(Map.Entry<String, String> entry : headers.entrySet())
				post.addHeader(entry.getKey(), entry.getValue());
			
			HttpResponse response = client.execute(post);
			HttpEntity entity = response.getEntity();
			
			if(entity == null)
				throw new NullPointerException();
			
			result = JsonHelper.getAsJson(IOUtils.toString(entity.getContent(), "UTF-8"));
		} catch (Exception e) {
			log("Failed to perform POST request");
			e.printStackTrace();
			return null;
		}
		
		return result;
	}
	
	private String getPostDataAsString(ArrayList<NameValuePair> postData) {
		String postDataStr = "";
		for(NameValuePair pair : postData) {
			postDataStr = postDataStr.concat(pair.getName());
			postDataStr = postDataStr.concat("=");
			postDataStr = postDataStr.concat(pair.getValue());
			postDataStr = postDataStr.concat("&");
		}
		
		return postDataStr.substring(0, postDataStr.length() - 1);
	}
	
	private LinkedHashMap<String, String> createHeaders(ArrayList<NameValuePair> postData) {
		LinkedHashMap<String, String> headers = new LinkedHashMap<String, String>(2);
		
		headers.put("Key", this.key);
		
		String postDataStr = getPostDataAsString(postData);
		String sign = HashHelper.getHmacSHA512(postDataStr, this.secret);
		
		if(sign == null) {
			log("Failed to calculate Hmac-SHA512 of post data: \"".concat(postDataStr).concat("\""));
			return null;
		}
		
		log("Calculated Hmac-SHA512: \"".concat(sign).concat("\" of data: \"").concat(postDataStr).concat("\""));
		
		headers.put("Sign", sign);
		
		return headers;
	}
}
