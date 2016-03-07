
/* This Program was developed by Swati Mittal. 
 * Date - 06-March-2016
 * 
 * This Module accepts the Indicators of Compromise(IOC) like Ip address, port
 * as arguments and look up all information related to the IOC(s) in the sources isc.sans.edu. 
 * Module will parse the JSONObject in to the required field
 * Program correlate the data and provide a meaningful analysis of the IOC.
 * 
 */
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class SansAPI {

	static HTTPConnection con = new HTTPConnection();

	// Base URL of the sans
	static String url = "https://isc.sans.edu/api";
	static JSONParser parser = new JSONParser();
	static Display display = new Display();

	/*
	 * This method take the ipaddress as the argument merge it with base url of
	 * the Sans. call the connection class for HTTP connection.Receive data as a
	 * JSON object. Parse the JSOnobject do the analysis and return the relevant
	 * value.
	 */

	public static int getDataIP(String ipAddress) throws ParseException, IOException, URISyntaxException {

		// create the API after merging the base url, ipaddress and the return
		// format
		String SansApi = url + "/ip/" + ipAddress + "?json";

		// Call Connection class for HTTP connection.Receives the JSONObject
		JSONObject jsonObject = con.getConnection(SansApi);
		if (jsonObject == null) {
			String line = "<div>" + "<h3>" + "Source : " + "isc.sans.edu " + "</h3>" + "\n" + "<p>" + "ip not found "
					+ "</p>" + "</div>";
			display.print(line);

			return -1;
		}
		String ip = (String) jsonObject.get("ip").toString();

		// Parse the JOSNObject in the required field.
		Object object = parser.parse(ip);
		JSONObject jsonObject2 = (JSONObject) object;

		String network = (String) jsonObject2.get("network");
		String attacks = (String) jsonObject2.get("attacks");
		String asabusecontact = (String) jsonObject2.get("asabusecontact");
		String opendnsresolver = (String) jsonObject2.get("opendnsresolver");
		String ascountry = (String) jsonObject2.get("ascountry");
		String maxrisk = (String) jsonObject2.get("maxrisk");
		String asname = (String) jsonObject2.get("asname");

		String line;
		// Print the output in the Web HTML file
		line = "<div>" + "\n" + "<h3>" + "Source : " + "isc.sans.edu" + "</h3>" + "\n" + "<p>" + "Name : " + asname
				+ "</p>" + "\n" + "<p>" + "Attacks : " + attacks + "</p>" + "\n" + "<p>" + "Abuse Contact : "
				+ asabusecontact + "</p>" + "\n" + "<p>" + "Country :" + ascountry + "</p>" + "\n" + "<p>"
				+ "Maximum risk :" + maxrisk + "</p>" + "\n" + "<p>" + "Open Dns Resolver :" + opendnsresolver + "</p>"
				+ "\n" + "<p>" + "Network :" + network + "</p>" + "\n" + "</div>";

		display.print(line);
		if (asabusecontact == null) {
			return 0;
		}

		return 1;

	}

	/*
	 * This method take the port as the argument merge it with base url of the
	 * Sans. call the connection class for HTTP connection.Receive data as a
	 * JSON object. Parse the JSOnobject do the analysis and return the relevant
	 * value.
	 */

	public static int getDataport(String port) throws ParseException, IOException, URISyntaxException {

		// create the API after merging the base url, port and the return format
		String SansApi = url + "/port/" + port + "?json";

		// Call Connection class for HTTP connection.Receives the JSONObject
		JSONObject jsonObject = con.getConnection(SansApi);

		// if IOC not found it will return -1
		if (jsonObject == null) {
			String line = "<div>" + "<h3>" + "Source : " + "isc.sans.edu " + "</h3>" + "\n" + "<p>" + "port not found "
					+ "</p>" + "</div>";
			display.print(line);
			return -1;
		}

		// if IOC found it will parse the JSON object
		String data = (String) jsonObject.get("data").toString();
		Object object = parser.parse(data);
		JSONObject jsonObject2 = (JSONObject) object;

		String date = (String) jsonObject2.get("date");
		Long targets = (Long) jsonObject2.get("targets");
		Long records = (Long) jsonObject2.get("records");

		String services = (String) jsonObject.get("services").toString();
		Object object2 = parser.parse(services);
		JSONObject jsonObject3 = (JSONObject) object2;

		String udp = (String) jsonObject3.get("udp").toString();
		String tcp = (String) jsonObject3.get("tcp").toString();

		Object object3 = parser.parse(udp);
		JSONObject jsonObject4 = (JSONObject) object3;

		String nameUdp = (String) jsonObject4.get("name").toString();
		String serviceUdp = (String) jsonObject4.get("service").toString();

		Object object4 = parser.parse(tcp);
		JSONObject jsonObject5 = (JSONObject) object4;

		String nameTcp = (String) jsonObject5.get("name").toString();
		String serviceTcp = (String) jsonObject5.get("service").toString();

		String line;
		// print the output in the the web HTML file
		line = "<div>" + "\n" + "<h3>" + "Source : " + "isc.sans.edu" + "</h3>" + "\n" + "<p>" + "Date : " + date
				+ "</p>" + "\n" + "<p>" + "Targets : " + targets + "</p>" + "\n" + "<p>" + "Records :" + records
				+ "</p>" + "\n" + "<p>" + "UDP Name :" + nameUdp + "</p>" + "\n" + "<p>" + "UDP Service :" + nameUdp
				+ "</p>" + "\n" + "<p>" + "TCP Name :" + nameTcp + "</p>" + "\n" + "<p>" + "TCP Service :" + nameTcp
				+ "</p>" + "\n" + "</div>";

		display.print(line);

		if (nameTcp.contains("HTTP") || nameUdp.contains("HTTP")) {
			return 0;
		}
		return 1;

	}

}
