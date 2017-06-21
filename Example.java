import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;

import com.google.gson.JsonObject;

public class Example {

	public static void main(String[] args) throws IOException {
		String key = null;
		String secret = null;
		/**
		 * Expect 1 or 2 arguments; the key and secret or a file containing both.
		 */
		if(args.length < 1 || args.length > 2) {
			log("Expected 1 or 2 arguments, received ".concat(String.valueOf(args.length)));
			return;
		} else if(args.length == 1) {
			String fileName = args[0];
			
			File file = new File(fileName);
			
			if(!file.exists()) {
				log("Received 1 argument, but it is not a file");
				return;
			}
			
			BufferedReader reader = null;
			reader = new BufferedReader(new FileReader(file));
			
			/**
			 * Expect 1 key and 1 secret in the file
			 */
			String buffer = null;
			while((buffer = reader.readLine()) != null) {
				if(BTCE_API_Lib.isValidAPIKey(buffer)) {
					if(key != null) {
						log("Multiple API keys found in file");
						reader.close();
						return;
					}
					
					key = buffer;
				} else if(BTCE_API_Lib.isValidSecret(buffer)) {
					if(secret != null) {
						log("Multiple API secrets found in file");
						reader.close();
						return;
					}
					
					secret = buffer;
				} else {
					log("Ignoring file line: \"".concat(buffer).concat("\""));
				}
			}
			
			reader.close();
		} else if(args.length == 2) {
			key = args[0];
			secret = args[1];
			
			if(!BTCE_API_Lib.isValidAPIKey(key)) {
				log("Received invalid API key: \"".concat(key).concat("\""));
				return;
			}
			
			if(!BTCE_API_Lib.isValidSecret(secret)) {
				log("Received invalid API secret: \"".concat(secret).concat("\""));
				return;
			}
		}
		
		if(key == null) {
			log("No API keys found");
			return;
		}
		
		if(secret == null) {
			log("No API secrets found");
			return;
		}
		
		log("Found API key: \"".concat(key).concat("\""));
		log("Found API secret: \"".concat(secret).concat("\""));
		
		/*
		 * Now that the key and secret have been acquired,
		 * we can finally use the library.
		 */
		BTCE_API_Lib apiLib = new BTCE_API_Lib(key, secret);
		
		ArrayList<NameValuePair> postData = new ArrayList<NameValuePair>();
		postData.add(new BasicNameValuePair("method", "getInfo"));
		
		JsonObject result = apiLib.performAuthorizedRequest(postData);
		log("getInfo result: ".concat(result.toString()));
		
		if(result.get("success") == null) {
			log("Couldn't retrieve parameter: 'success'");
			return;
		}
		
		if(result.get("success").getAsInt() == 0) {
			log("getInfo failed, adjusting nonce and requesting again");
			BTCE_API_Lib.fixNonce(result);
			result = apiLib.performAuthorizedRequest(postData);
			log("getInfo result: ".concat(result.toString()));
		}
		
		postData.clear();
		postData.add(new BasicNameValuePair("method", "Trade"));
		postData.add(new BasicNameValuePair("pair", "btc_usd"));
		postData.add(new BasicNameValuePair("type", "sell"));
		postData.add(new BasicNameValuePair("rate", "2700"));
		postData.add(new BasicNameValuePair("amount", "0.00"));
		
		result = apiLib.performAuthorizedRequest(postData);
		log("Sell result: ".concat(result.toString()));
	}

	public static void log(String str) {
		System.out.println("[Example.java] ".concat(str));
	}
}
