/* This Program was developed by Swati Mittal. 
 * Date - 06-March-2016
 * 
 * This Module create the HTTP Connection. Send the url of the source as GET and POST method 
 * to the server. Receives the data as string. Convert the data to the JSON Object. 
 * 
 */

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class HTTPConnection {

	// This method establish a HTTP connection. Send the URL to the
	// sever.Request the GET method.
	// receives the data in the form of string
	public static JSONObject getConnection(String url) {
		try {

			URL obj = new URL(url);

			// Establish the HTTP connection through GET method
			HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
			con.setRequestMethod("GET");

			// Store the response code from the server
			int responseCode = con.getResponseCode();
			BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
			String inputLine;
			StringBuffer response = new StringBuffer();

			while ((inputLine = in.readLine()) != null) {
				response.append(inputLine);
			}

			// Convert the string into JSON object
			String s = response.toString();
			
			JSONParser parser = new JSONParser();
			Object object = parser.parse(s);

			JSONObject jsonObject = (JSONObject) object;

			in.close();

			// return the JSONobject

			return jsonObject;

		} catch (Exception e) {
			return null;
		}

	}

	/*
	 * This method establish a HTTP connection. Send the URL to the
	 * sever.Request the POST method. Send the parameters url, test url, apikey
	 * to the server. Receives the data in the form of string
	 */
	static JSONObject getConnectionPOST(String url, String urlCheck, String apikey) throws Exception {

		try {
			URL obj = new URL(url);

			// Establish the HTTP connection through POST method
			HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();

			// add reuqest header
			con.setRequestMethod("POST");

			// Send the url parameters to the server
			String urlParameters = "url=" + urlCheck + "&format=" + "json" + "&api_key=" + apikey;

			// Send post request
			con.setDoOutput(true);

			DataOutputStream wr = new DataOutputStream(con.getOutputStream());
			wr.writeBytes(urlParameters);
			wr.flush();
			wr.close();

			// Store the response code
			int responseCode = con.getResponseCode();

			BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
			String inputLine;
			StringBuffer response = new StringBuffer();

			while ((inputLine = in.readLine()) != null) {
				response.append(inputLine);
			}
			String s = response.toString();

			// Convert the string in to JSONobject
			JSONParser parser = new JSONParser();
			Object object = parser.parse(s);

			JSONObject jsonObject = (JSONObject) object;

			in.close();

			// Return the JSONobject
			return jsonObject;

		} catch (Exception e) {

			return null;
		}

	}

	/*
	 * This method establish a HTTP connection. Send the URL to the
	 * sever.Request the GET method. Receives the data in the form of string
	 */

	public static String getConnectionGoogle(String url) {
		try {

			URL obj = new URL(url);

			// Establish the HTTP connection through GET method
			HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
			con.setRequestMethod("GET");

			// Store the response code
			int responseCode = con.getResponseCode();
			String result;

			// check if response code is 204
			if (responseCode == 204) {
				result = "OK";
				return result;
			}
			BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
			String inputLine;
			StringBuffer response = new StringBuffer();

			while ((inputLine = in.readLine()) != null) {
				response.append(inputLine);
			}

			result = response.toString();
			in.close();

			// Return the string
			return result;

		} catch (Exception e) {
			// TODO: handle exception
			return null;
		}

	}

	/*
	 * This method establish a HTTP connection. Send the URL to the
	 * sever.Request the GET method. Receives the data in the form of string
	 */
	static JSONObject getConnectionPOSTmalwr(String url, String filepath, String apikey) throws Exception {

		try {
			URL obj = new URL(url);
			HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();

			// add reuqest header
			con.setRequestMethod("POST");

			String urlParameters = "api_key=" + apikey + "&shared=yes" + "&file=@/" + filepath + "/to/binary";
			
			// Send post request
			con.setDoOutput(true);
			DataOutputStream wr = new DataOutputStream(con.getOutputStream());
			wr.writeBytes(urlParameters);
			wr.flush();
			wr.close();

			int responseCode = con.getResponseCode();
			BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
			String inputLine;
			StringBuffer response = new StringBuffer();

			while ((inputLine = in.readLine()) != null) {
				response.append(inputLine);
			}
			String s = response.toString();
		
			JSONParser parser = new JSONParser();
			Object object = parser.parse(s);

			JSONObject jsonObject = (JSONObject) object;

			in.close();

			return jsonObject;

		} catch (Exception e) {
			// TODO: handle exception
			return null;
		}
	}

}
