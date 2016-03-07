
/* This Program was developed by Swati Mittal. 
 * Date - 06-March-2016
 * 
 * This Module accepts the Indicators of Compromise(IOC) like url
 * as arguments and look up all information related to the IOC(s) in the sources Phish tank. 
 * Module will parse the JSONObject in to the required field
 * Program correlate the data and provide a meaningful analysis of the IOC.
 * 
 */
import java.net.URLEncoder;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class Phishtank {

	static HTTPConnection con = new HTTPConnection();

	static String apikey = "0097a8ad7aa83ee076ba3a90b057213590823873aee13a7b274a9b4ab15380d1";

	// Base Url of Phishtank
	static String url = "https://checkurl.phishtank.com/checkurl/";
	static JSONParser parser = new JSONParser();
	static Display display = new Display();

	/*
	 * This method take the url as the argument merge it with base url of the
	 * phishtank. call the connection class for HTTP connection.Receive data as
	 * a JSON object. Parse the JSOnobject do the analysis and return the
	 * relevant value.
	 */
	public static int getDataURL(String urlTest) throws Exception {

		// encode the url is need to be test in the UTF-8
		String urlencode = URLEncoder.encode(urlTest, "UTF-8");

		/*
		 * Send the baseurl, encoded url, and apikey as a argument in the
		 * Connection class function getConnectionPOSt(). Receives the data in
		 * JSONObject format
		 */

		JSONObject jsonObject = con.getConnectionPOST(url, urlencode, apikey);
		if (jsonObject == null) {
			String line = "<div>" + "<h3>" + "Source : " + "Phish Tank" + "</h3>" + "\n" + "<p>" + "url not found "
					+ "</p>" + "</div>";
			display.print(line);
			return -1;
		}

		// parse the JSON Object
		String line;
		String meta = (String) jsonObject.get("meta").toString();
		String results = (String) jsonObject.get("results").toString();

		Object object = parser.parse(meta);
		JSONObject jsonObject2 = (JSONObject) object;

		Object object2 = parser.parse(results);
		JSONObject jsonObject3 = (JSONObject) object2;

		String timeStamp = (String) jsonObject2.get("timestamp");
		boolean inDatabase = (boolean) jsonObject3.get("in_database");

		if (!inDatabase) {
			line = "<div>" + "<h3>" + "Source : " + "Phish Tank" + "</h3>" + "\n" + "<p>" + "url not found " + "</p>"
					+ "</div>";
			display.print(line);
			return -1;
		}

		if (inDatabase) {
			boolean verified = (boolean) jsonObject3.get("verified");
			String verified_at = (String) jsonObject3.get("verified_at");
			boolean valid = (boolean) jsonObject3.get("valid");

			// Print the output in the web HTML file
			line = "<div>" + "\n" + "<h3>" + "Source : " + "Phish Tank" + "</h3>" + "\n" + "<p>" + "Timestamp : "
					+ timeStamp + "</p>" + "\n" + "<p>" + "Verified : " + verified + "</p>" + "\n" + "<p>"
					+ "Verified_at : " + verified_at + "</p>" + "\n" + "<p>" + "Valid : " + valid + "</p>" + "\n"
					+ "</div>";
			display.print(line);
			if (!verified) {
				return 1;
			}

		}
		return 0;

	}
}