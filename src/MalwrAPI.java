import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class MalwrAPI {

	static String apikey = "db656c617c9f42ccb914f0ce6ef19988";
	static String baseURL = "https://malwr.com/api/analysis/add/";
	static HTTPConnection con = new HTTPConnection();
	static JSONParser parser = new JSONParser();

	public static void main(String[] args) throws Exception {

		malwr_file_submission("test.txt", apikey);
	}

	public static void malwr_file_submission(String filepath, String apikey) throws Exception {

		JSONObject jsonObject = con.getConnectionPOST(baseURL, filepath, apikey);

	}

}
