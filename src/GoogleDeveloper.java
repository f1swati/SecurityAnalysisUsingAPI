
/* This Program was developed by Swati Mittal. 
 * Date - 06-March-2016
 * 
 * This Module accepts the Indicators of Compromise(IOC) like url
 * as arguments and look up all information related to the IOC(s) in the sources Google safe browsing. 
 * Module will parse the JSONObject in to the required field
 * Program correlate the data and provide a meaningful analysis of the IOC.
 * 
 */
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;

import org.json.simple.JSONObject;

public class GoogleDeveloper {

	static HTTPConnection con = new HTTPConnection();
	static String apikey = "AIzaSyA1vhiu_qHDXICamERJkk-rtXJwMc0KhAc";

	// Base url of the google safe browsing
	static String baseURL = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=demo-app&";
	static Display display = new Display();

	/*
	 * This method take the url as the argument merge it with base url of the
	 * Google safe browsing. call the connection class for HTTP
	 * connection.Receive data as a JSON object. Parse the JSOnobject do the
	 * analysis and return the relevant value.
	 */
	public static int getDataURL(String urlTest) throws IOException, URISyntaxException {

		// Convert the url need to be test in the UTF-8 format
		String Urlencode = URLEncoder.encode(urlTest, "UTF-8");

		// Merge the base url with the apikey, appver , and the encoded url
		String safeBrowsingUrl = baseURL + "key=" + apikey + "&appver=1.5.2&pver=3.1&" + "url=" + Urlencode;

		// Call Connection class for HTTP connection.Receives the data as a string
		String result = con.getConnectionGoogle(safeBrowsingUrl);

		if (result.equals(null)) {
			String line = "<div>" + "<h3>" + "Source : " + "Phish Tank" + "</h3>" + "\n" + "<p>" + "url not found "
					+ "</p>" + "</div>";
			display.print(line);
			return -1;
		}

		// print the output in the web HTML file
		String line = "<div>" + "\n" + "<h3>" + "Source : " + "Google Safe Browsing" + "</h3>" + "\n" + "<p>"
				+ "Result : " + result + "</p>" + "\n" + "</div>";
		display.print(line);

		if (result.equals("OK")) {
			return 0;
		}
		return 1;

	}

}
