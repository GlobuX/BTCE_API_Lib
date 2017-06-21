import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class JsonHelper {

	public static JsonObject getAsJson(String str) {
		return new JsonParser().parse(str).getAsJsonObject();
	}
}
