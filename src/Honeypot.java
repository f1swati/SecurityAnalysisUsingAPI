
/* This Program was developed by Swati Mittal. 
 * Date - 06-March-2016
 * 
 * This Module accepts the Indicators of Compromise(IOC) like Ip address, port, source,
 * domain, URl as arguments and look up all information related to the IOC(s)
 * in the source Honeypot. Module will parse the JSONObject in to the required fields
 * Program correlate the data and provide a meaningful analysis of the IOC.
 * 
 */

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class Honeypot {

	// Define all the static fields need to parse from the honeypot data base
	static String ident;
	static String timestamp;
	static Boolean normalised;
	static String payload;
	static String pattern;
	static String time;
	static String filename;
	static String request_raw;
	static String request_url;
	static Long attackerPort;
	static Long victimPort;
	static String victimIP;
	static String attackerIP;
	static String connectionType;
	static String channel;

	// Define a function take the IOC input and retreive the data from the
	// Honeypot database.
	public static int getData(String input, int choice) throws IOException, ParseException, URISyntaxException {
		int count = -1;
		int response = 0;
		int noOfAttack = 0;
		boolean first = true;

		Display display = new Display();
		JSONParser parser = new JSONParser();

	//	FileReader jsonfile = new FileReader("resources/honeypot.json");
		
		InputStream in = Honeypot.class.getClassLoader().getResourceAsStream("honeypot.json"); 
		BufferedReader br = new BufferedReader(new InputStreamReader(in));
		
		String sCurrentLine = " ";
		String[] key;
		JSONArray array = new JSONArray();

		String line = "<h3>" + "Source :" + " Honeypot" + "</h2>" + "\n";
		display.print(line);
		// Read the record one by one from the database and stored the record in
		// JSONObject in to an array
		while ((sCurrentLine = br.readLine()) != null) {

			key = sCurrentLine.split(" } ");
			Object obj = parser.parse(key[0]);
			JSONObject jsonObject = (JSONObject) obj;
			array.add(jsonObject);

		}
		ArrayList templist = new ArrayList();
		String timestapend = null;
		// Read the JSON object from the array and parse the JSON object in the
		// required fields
		for (int i = 0; i < array.size(); i++) {
			JSONObject objectNew = (JSONObject) array.get(i);

			// Parse field ident, timestamp, normalised, payload from the jSon
			// object
			ident = (String) objectNew.get("ident");

			JSONObject timesObject = (JSONObject) objectNew.get("timestamp");
			timestamp = (String) timesObject.get("$date");
			normalised = (boolean) objectNew.get("normalized");
			payload = (String) objectNew.get("payload");

			Object objPayload = parser.parse(payload);
			JSONObject objectPay = (JSONObject) objPayload;
			ArrayList list = new ArrayList();
			pattern = (String) objectPay.get("pattern");
			time = (String) objectPay.get("time");
			filename = (String) objectPay.get("filename");
			/*
			 * JSONArray sourceArray = new JSONArray();
			 * sourceArray.add(objectPay.get("source"));
			 * 
			 * if (sourceArray.get(0) != null) { String a =
			 * sourceArray.get(0).toString(); String[] sourceKeys;
			 * StringTokenizer st = new StringTokenizer(a, "[,]\"\" ");
			 * 
			 * while (st.hasMoreTokens()) { list.add(st.nextToken().toString());
			 * 
			 * } String aString = (String) list.get(0); String bString =
			 * (String) list.get(1); }
			 */

			request_raw = (String) objectPay.get("request_raw");
			request_url = (String) objectPay.get("request_url");
			attackerPort = (Long) objectPay.get("attackerPort");
			victimPort = (Long) objectPay.get("victimPort");
			victimIP = (String) objectPay.get("victimIP");
			attackerIP = (String) objectPay.get("attackerIP");
			connectionType = (String) objectPay.get("connectionType");
			channel = (String) objectNew.get("channel");

			// This is to retrieve the data against the IOC

			String temp = "0";
			switch (choice) {

			// If IOC is ip address it will goto case 1
			case 1:

				// if its ip address is safe it will return 0
				if (victimIP != null) {

					if (victimIP.equals(input) && !templist.contains(attackerIP)) {
						response++;
						templist.add(attackerIP);
						display.print(print());
						count = 0;
					}

				}

				// if its ip address is not safe it will return 1
				if (attackerIP != null) {
					if (attackerIP.equals(input)) {
						noOfAttack++;
						if (noOfAttack == 1) {
							display.print(print());
						}
						timestapend = timestamp;
						count = 1;
					}

				}

				break;
			// If IOC is port it will go in case 2
			case 2:

				// If port is safe it will return 0
				if (victimPort != null) {
					if (victimPort == Integer.parseInt(input) && !templist.contains(attackerIP)) {
						if(first == true){
							line = "<l>" + "Victim port: " + victimPort + "</l>";
							display.print(line);
							first = false;
						}
						templist.add(attackerIP);
						display.print(print());
						count = 0;
					}
					// If port is unsafe it will return 1
				}
				if (attackerPort != null ) {
					if (attackerPort == Integer.parseInt(input) && !templist.contains(attackerIP)) {
						if(first == true){
							line = "<l>" + "Attacker port: " + attackerPort + "</l>";
							display.print(line);
							first = false;
						}
						templist.add(attackerIP);
						display.print(print());
						count = 1;
					}
				}
				break;
			// If IOC is url it will go in case 3
			case 3:

				// if url is unsafe it will return 1;
				if (request_url != null) {
					if (request_url == input) {
						display.print(print());
						count = 1;
					}
				}
				break;
			default:
				break;
			}
		}

		if (noOfAttack > 1) {
			line = "<l>" + " Last TimeStamp " + timestapend + "</l>" + "\n" + "<l style=\"padding-left:20px;color:red\">" + " Number of attacks during duration " + noOfAttack
					+ "</l>";
			display.print(line);
		}
		
		if (response > 1) {
			line = "<l style=\"color:red\">" + " Number of unique IP attack "  + response + "</l>";
					
			display.print(line);
		}
		if (count == -1) {
			// if ip address not found it will return -1
			// Display result on the web browser
			line = "<p>" + "not found " + "</p>";
			
			display.print(line);
			
		}

		
		return count;

	}

	// Print the fetched data on the web browser
	public static String print() {

		String line;
		line = "<div>" + "<l>" + "Victim Ip: " + victimIP + "</l>" +  "<l style=\"padding-left:20px\">" + " Attacker Ip: " + attackerIP
				+ "</l>" + "\n" + "<l style=\"padding-left:20px\">" + "Connection Type :" + connectionType + "</l>" + "\n" + "<l style=\"padding-left:20px\">"
				+ "Time Stamp :" + timestamp + "</l>" + "</div>";

		return line;

	}

}
