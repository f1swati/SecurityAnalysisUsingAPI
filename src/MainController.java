
/* This Program was developed by Swati Mittal. 
 * Date - 06-March-2016
 * 
 * Objective -  
 * This Program accepts the Indicators of Compromise(IOC) like Ip address, port, source,
 * domain, URl as arguments to the program and look up all information related to the IOC(s)
 * in the sources like Honeypot, isc.sans.edu, Virustotal, malwr, phishtank and google. 
 * Program correlate the data and provide a meaningful analysis of the IOC. This code display 
 * the analysis  on a web browser in use friendly way.
 * 
 * Constraints:
 * I have API to of isc.sans, Virustotal, Malwr, Phistank and google.
 * The server of these above should be up for fetching the data.
 * 
 * To ensure that program performs in case of higher loads I have tested it for 7 test cases.
 * I have included all the test cases in the file instruction.pdf. 
 * instruction.pdf is in the submission zipfolder
 * 
 * 
 */

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.regex.Pattern;

import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.UrlValidator;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class MainController {

	// Instantiate the java classes to call their respective API against the
	// required IOC

	static SansAPI sansApi = new SansAPI();
	static VirusTotal virustotal = new VirusTotal();
	static Phishtank phishtank = new Phishtank();
	static GoogleDeveloper googledev = new GoogleDeveloper();
	static Honeypot honeyPot = new Honeypot();
	static Display display = new Display();

	public static void main(String[] args) throws Exception {

		mainFunction(args);

	}

	/*
	 * This function is the main function first it will check the type of IOC
	 * like IP address, url , domain, port. Call the functions of different
	 * sources to fetch the relevant data. Do the meaning full analysis and
	 * print them in the HTML web browser file.
	 */

	public static void mainFunction(String[] args) throws Exception {
		int countSafe = 0;
		int countThreat = 0;
		int countNA = 0;
		int responseCode = 0;

		// This function call the methos of the Display class and creates a HTML
		// file
		display.createFile();

		// if no argument pass program will return after displaying the
		// following messages.
		if (args.length == 0) {
			String line = "<div>" + "<h2>" + "No Input " + "</h2>" + "</div>";
			display.print(line);
			display.browse();
			return;
		}

		// This loop is to check against all the arguments and fetch the
		// relevant data from the sources
		for (int i = 0; i < args.length; i++) {

			// These variables is to keep track the status of IOC from the all
			// sources
			countThreat = 0;
			countNA = 0;
			countSafe = 0;

			/*
			 * Call the function checkforIP() to check if the argument is
			 * Ipaddress. if it IP address than it will go inside
			 */

			if (checkforIp(args[i])) {
				String line = "<div>" + "<h2>" + "Requested Information of IP " + args[i] + "</h2>" + "</div>" + "\n";
				display.print(line);

				// Check the ip address in the honeypot source
				System.out.println("Scanning Honeypot Source....");
				responseCode = honeyPot.getData(args[i], 1);

				/*
				 * response code is the return code form the source. If IOP is
				 * safe return code is 0 If IOP is unsafe return code is 1 and
				 * if IOP is not found return code is -1
				 * 
				 */
				if (responseCode == 1)
					countThreat++;
				if (responseCode == 0)
					countSafe++;
				if (responseCode == -1)
					countNA--;

				// Check the ip address in the Sans source
				System.out.println("Scanning SansAPI Source....");
				responseCode = sansApi.getDataIP(args[i]);
				if (responseCode == 1)
					countThreat++;
				if (responseCode == 0)
					countSafe++;
				if (responseCode == -1)
					countNA--;

				// Check the ip address in the Virus Total source
				System.out.println("Scanning Virus Total Source....");
				responseCode = virustotal.getDataIP(args[i]);
				if (responseCode == 1)
					countThreat++;
				if (responseCode == 0)
					countSafe++;
				if (responseCode == -1) {
					countNA--;
				}

				/*
				 * if countThreat is grater than one means more than one
				 * resources confirmed that the IOP is not safe. if countsafe is
				 * 0 it means IOP is safe and if countNA it means record not
				 * found in any source. As per the analysis it will print the
				 * result in the HTML file.
				 * 
				 */
				if (countThreat >= 1) {
					line = "<div>" + "<h2 style=\"color:red\">" + "Result :  IP " + args[i] + " is not safe." + "</h2>"
							+ "</div>" + "\n";
				} else if (countSafe >= 0) {
					line = "<div>" + "<h2 style=\"color:green\">" + "Result :  IP " + args[i] + " is safe" + "</h2>"
							+ "</div>" + "\n";
				} else if (countNA < 0) {
					line = "<div>" + "<h2 style=\"color:yellow\">" + "Result :  IP " + args[i] + " not found" + "</h2>"
							+ "</div>" + "\n";
				}

				display.print(line);
				line = "<hr style=\"background-color:lightgrey\"></hr>";
				display.print(line);

			} else if (checkforfile(args[i])) {
				System.out.println("Its a file :" + args[i]);
			}
			/*
			 * Call the function checkforport() to check if the argument is
			 * port. if it is port than it will go inside
			 */
			else if (checkforport(args[i])) {
				String line = "<div>" + "<h2>" + "Requested Information of Port " + args[i] + "</h2>" + "</div>" + "\n";
				display.print(line);

				System.out.println("Scanning Honeypot Source....");
				responseCode = honeyPot.getData(args[i], 2);
				if (responseCode == 1)
					countThreat++;
				if (responseCode == 0)
					countSafe++;
				if (responseCode == -1)
					countNA--;

				System.out.println("Scanning SansAPI Source....");
				responseCode = sansApi.getDataport(args[i]);
				if (responseCode == 1)
					countThreat++;
				if (responseCode == 0)
					countSafe++;
				if (responseCode == -1)
					countNA--;

				if (countThreat >= 1) {
					line = "<div>" + "<h2 style=\"color:red\">" + "Result :  Port " + args[i] + " is not safe."
							+ "</h2>" + "</div>" + "\n";
				} else if (countSafe >= 0) {
					line = "<div>" + "<h2 style=\"color:green\">" + "Result :  Port " + args[i] + " is safe" + "</h2>"
							+ "</div>" + "\n";
				} else if (countNA < 0) {
					line = "<div>" + "<h2 style=\"color:yellow\">" + "Result :  Port " + args[i] + " not fountd"
							+ "</h2>" + "</div>" + "\n";
				}

				display.print(line);
				line = "<hr style=\"background-color:lightgrey\"></hr>";
				display.print(line);

			} /*
				 * Call the function checkforurl() to check if the argument is
				 * url. if it is url than it will go inside
				 */
			else if (checkforurl(args[i])) {

				String line = "<div>" + "<h2>" + "Requested Information of URL " + args[i] + "</h2>" + "</div>" + "\n";
				display.print(line);

				System.out.println("Scanning Honeypot Source....");
				responseCode = honeyPot.getData(args[i], 3);
				if (responseCode == 1)
					countThreat++;
				if (responseCode == 0)
					countSafe++;
				if (responseCode == -1)
					countNA--;

				System.out.println("Scanning Virus Total Source....");
				responseCode = virustotal.getDataURL(args[i]);
				if (responseCode == 1)
					countThreat++;
				if (responseCode == 0)
					countSafe++;
				if (responseCode == -1)
					countNA--;

				System.out.println("Scanning Phish tank Source....");
				responseCode = phishtank.getDataURL(args[i]);
				if (responseCode == 1)
					countThreat++;
				if (responseCode == 0)
					countSafe++;
				if (responseCode == -1)
					countNA--;

				System.out.println("Scanning Google safe browsing....");
				responseCode = googledev.getDataURL(args[i]);
				if (responseCode == 1)
					countThreat++;
				if (responseCode == 0)
					countSafe++;
				if (responseCode == -1)
					countNA--;

				if (countThreat >= 1) {
					line = "<div>" + "<h2 style=\"color:red\">" + "Result :  URL " + args[i] + " is not safe." + "</h2>"
							+ "</div>" + "\n";
				} else if (countSafe >= 0) {
					line = "<div>" + "<h2 style=\"color:green\">" + "Result :  URL " + args[i] + " is safe" + "</h2>"
							+ "</div>" + "\n";
				} else if (countNA < 0) {
					line = "<div>" + "<h2 style=\"color:yellow\">" + "Result :  URL " + args[i] + " not fount" + "</h2>"
							+ "</div>" + "\n";
				}
				display.print(line);
				line = "<hr style=\"background-color:lightgrey\"></hr>";
				display.print(line);

			}
			/*
			 * Call the function checkfordomain() to check if the argument is
			 * domain. if it is domain than it will go inside
			 */
			else if (checkfordomain(args[i])) {

				String line = "<div>" + "<h2>" + "Requested Information of Domain " + args[i] + "</h2>" + "</div>"
						+ "\n";
				display.print(line);

				System.out.println("Scanning Virus Total Source....");
				responseCode = virustotal.getDataDomain(args[i]);

				if (responseCode == 1)
					countThreat++;
				if (responseCode == 0)
					countSafe++;
				if (responseCode == -1)
					countNA--;

				if (countThreat >= 1) {
					line = "<div>" + "<h2 style=\"color:red\">" + "Result :  domain " + args[i] + " is not safe."
							+ "</h2>" + "</div>" + "\n";
				} else if (countSafe > 0) {
					line = "<div>" + "<h2 style=\"color:green\">" + "Result :  domain " + args[i] + " is safe" + "</h2>"
							+ "</div>" + "\n";
				} else if (countNA < 0) {
					line = "<div>" + "<h2 style=\"color:yellow\">" + "Result :  domain " + args[i] + " not found"
							+ "</h2>" + "</div>" + "\n";
				}
				display.print(line);
				line = "<hr style=\"background-color:lightgrey\"></hr>";
				display.print(line);
			}
		}
		display.browse();

	}

	// This function checks if the IOC is Ip
	private static boolean checkforIp(String ip) {
		Pattern PATTERN = Pattern.compile("^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");
		boolean validate = PATTERN.matcher(ip).matches();
		return validate;
	}

	// This function checks if the IOC is file
	private static boolean checkforfile(String fileName) {
		File f = new File(fileName);
		return f.isFile();
	}

	// This function checks if the IOC is port
	private static boolean checkforport(String port) {
		try {
			int portNumber = Integer.parseInt(port);
			if (portNumber < 65536)
				return true;
		} catch (Exception e) {
			return false;
		}
		return false;
	}

	// This function checks if the IOC is url
	private static boolean checkforurl(String url) {
		UrlValidator urlValidator = new UrlValidator();

		return urlValidator.isValid(url);
	}

	// This function checks if the IOC is domain
	private static boolean checkfordomain(String domain) {
		return DomainValidator.getInstance().isValid(domain);
	}

}
