
/* This Program was developed by Swati Mittal. 
 * Date - 06-March-2016
 * 
 * This Module accepts the Indicators of Compromise(IOC) like Ip address, port, url
 * as arguments and look up all information related to the IOC(s) in the sources Virus Total. 
 * Module will parse the JSONObject in to the required field
 * Program correlate the data and provide a meaningful analysis of the IOC.
 * 
 */

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URISyntaxException;
import java.util.Iterator;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class VirusTotal {

	static HTTPConnection con = new HTTPConnection();

	// Base url of the Virustotal
	static String url = "https://www.virustotal.com/vtapi/v2";
	static String apikey = "14feb6680ca4ba839ae24aa49f3baa8b52609f4da81dec844f2e464911a8ae0c";
	static Display display = new Display();
	static JSONParser parser = new JSONParser();

	/*
	 * This method take the ipaddress as the argument merge it with base url of
	 * the Virustotal. call the connection class for HTTP connection.Receive
	 * data as a JSON object. Parse the JSOnobject do the analysis and return
	 * the relevant value.
	 */
	public static int getDataIP(String ip) throws IOException, URISyntaxException {

		// merge ip address and api key with the base url
		String virustotalURL = url + "/ip-address/report?ip=" + ip + "&" + "apikey=" + apikey;
	
		// Call Connection class for HTTP connection.Receives the JSONObject
		JSONObject jsonObject = con.getConnection(virustotalURL);
		if (jsonObject == null) {
			String line = "<div>" + "<h3>" + "Source : " + "Virus Total" + "</h3>" + "\n" + "<p>" + "ip not found "
					+ "</p>" + "</div>";
			display.print(line);
			return -1;
		}

		// Parse the JSON object
		String verbose_msg = (String) jsonObject.get("verbose_msg");
		if (verbose_msg.contains("Missing")) {
			String line = "<div>" + "<h3>" + "Source : " + "Virus Total" + "</h3>" + "\n" + "<p>" + "ip not found "
					+ "</p>" + "</div>";
			display.print(line);
			return -1;
		}

		String line;
		line = "<div>" + "<h3>" + "Source : " + "Virus Total" + "</h3>" + "\n";
		display.print(line);
		
		JSONArray jsonarray = (JSONArray) jsonObject.get("detected_urls");
		if (jsonarray != null) {
			for (int i = 0; i < jsonarray.size(); i++) {
				JSONObject jsonobject = (JSONObject) jsonarray.get(i);

				String url = (String) jsonobject.get("url");
				Long positive = (Long) jsonobject.get("positives");
				String scandate = (String) jsonobject.get("scan_date");
				line = "<p>" + "Infacted URL : " + url + "</p>" + "\n" + "<p>" + "Scan Date : " + scandate + "</p>"
						+ "\n";
				display.print(line);

			}
		}

		String country = (String) jsonObject.get("country");
		String asOwner = (String) jsonObject.get("as_owner");
		Long responseCode = (Long) jsonObject.get("response_code");
		String asn = (String) jsonObject.get("asn");

		// print the ouput to the web HTML file
		line = "<p>" + "Country : " + country + "</p>" + "\n" + "<p>" + "Owner : " + asOwner + "</p>" + "\n" + "<p>"
				+ "ASN :" + asn + "</p>" + "\n" + "</div>";

		display.print(line);
		return 1;
	}

	/*
	 * This method take the Url as the argument merge it with base url of the
	 * Virustotal. call the connection class for HTTP connection.Receive data as
	 * a JSON object. Parse the JSOnobject do the analysis and return the
	 * relevant value.
	 */

	public static int getDataURL(String urlTest) throws ParseException, IOException, URISyntaxException {

		
		// Merge base url with the test url and the api key
		String virustotal = url + "/url/report?resource=" + urlTest + "&" + "apikey=" + apikey;
		System.out.println(virustotal);
		// Call the connection class for HTTPconnection. Receives the JSONobject
		JSONObject jsonObject = con.getConnection(virustotal);
		if (jsonObject == null) {
			String line = "<div>" + "<h3>" + "Source : " + "Virus Total" + "</h3>" + "\n" + "<p>" + "url not found "
					+ "</p>" + "</div>";
			display.print(line);
			return -1;
		}
		
		String verbose_msg = (String) jsonObject.get("verbose_msg");
		if(verbose_msg.contains("resource is not")){
			String line = "<div>" + "<h3>" + "Source : " + "Virus Total" + "</h3>" + "\n" + "<p>" + "url not found "
					+ "</p>" + "</div>";
			display.print(line);
			return -1;
		}
		// parse the JSONObject
		String scan_date = (String) jsonObject.get("scan_date");
		String scans = (String) jsonObject.get("scans").toString();
		
		Object object = parser.parse(scans);
		JSONObject jsonObject2 = (JSONObject) object;

		String CLEANMX = (String) jsonObject2.get("CLEAN MX").toString();

		Object object2 = parser.parse(CLEANMX);
		JSONObject jsonObject3 = (JSONObject) object2;

		String result = (String) jsonObject3.get("result");

		// Print output to the web HTML file
		String line = "<div>" + "<h3>" + "Source : " + "Virus Total" + "</h3>" + "\n" + "<p>" + "Time Stamp : "
				+ scan_date + "</p>" + "\n" + "<p>" + "Result :" + result + "</p>" + "\n" + "</div>";
		display.print(line);
		if (result.equals("clean site")) {
			return 0;
		}
		return 1;
	}

	/*
	 * This method take the domain as the argument merge it with base url of the
	 * Virustotal. call the connection class for HTTP connection.Receive data as
	 * a JSON object. Parse the JSOnobject do the analysis and return the
	 * relevant value.
	 */
	public static int getDataDomain(String domain) throws ParseException, IOException, URISyntaxException {

		// Merge the base url with the domain and the apikey
		String virustotal = url + "/domain/report?domain=" + domain + "&" + "apikey=" + apikey;
		
		// Call the connection class for HTTP connection. Receives the
		// JSONobject
		JSONObject jsonObject = con.getConnection(virustotal);
		if (jsonObject == null) {
			String line = "<div>" + "<h3>" + "Source : " + "Virus Total" + "</h3>" + "\n" + "<p>" + "domain not found "
					+ "</p>" + "</div>";
			display.print(line);
			return -1;
		}
		
		String verbose_msg = (String) jsonObject.get("verbose_msg");
		if(verbose_msg.contains("Domain not found")){
			String line = "<div>" + "<h3>" + "Source : " + "Virus Total" + "</h3>" + "\n" + "<p>" + "domain not found "
					+ "</p>" + "</div>";
			display.print(line);
			return -1;
		}
		
		// Parse the JSONObject
		String BitDefender = (String) jsonObject.get("BitDefender category");

		String line = "<div>" + "<h3>" + "Source : " + "Virus Total" + "</h3>" + "\n";
		display.print(line);

		if (jsonObject.get("Webutation domain info") != null) {
			String Webutation = (String) jsonObject.get("Webutation domain info").toString();
			Object object = parser.parse(Webutation);
			JSONObject jsonObject2 = (JSONObject) object;

			Long safety = (Long) jsonObject2.get("Safety score");
			String adultContent = (String) jsonObject2.get("Adult content");
			String verdict = (String) jsonObject2.get("Verdict");

			// Print the output in the web HTML file
			line = "<p>" + "Safety Score : " + safety + "</p>" + "\n" + "<p>" + "Adult Content " + adultContent + "</p>"
					+ "\n" + "<p>" + "Verdict :" + verdict + "</p>" + "\n";
			display.print(line);
		}

		
		if(jsonObject.get("whois") != null){
			String whois = (String) jsonObject.get("whois").toString();
		line = "<p>" + "Owner : " + whois + "</p>" + "\n";
		display.print(line);
		}
		
		if(jsonObject.get("detected_urls") != null){
		JSONArray jsonarray = (JSONArray) jsonObject.get("detected_urls");
		for (int i = 0; i < jsonarray.size(); i++) {
			JSONObject jsonobject = (JSONObject) jsonarray.get(i);

			String url = (String) jsonobject.get("url");
			Long positive = (Long) jsonobject.get("positives");
			String scandate = (String) jsonobject.get("scan_date");

			// Print the output in the web HTML file
			line = "<p>" + "URL : " + url + "</p>" + "\n" + "<p>" + "Scan Date : " + scandate + "</p>" + "\n"
					+ "</div>";

			display.print(line);

		}}
		return 1;

	}

}
