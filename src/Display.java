/* This Program was developed by Swati Mittal. 
 * Date - 06-March-2016
 * 
 * This Module creates the HTML file. Write the header and footer to the HTML file. 
 * Write the output to the HTML file. Launch the web browser in your default browser. 
 * Display the result 
 */

import java.awt.Desktop;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;

public class Display {

	static boolean firstExecute;

	// location of the HTML file
	static String input = "index.html";
	static PrintWriter output;

	// This method creates the HTML file
	public static void createFile() throws IOException {
		
		// Check if the HTML file exists delete it and than recreate it
		if (!firstExecute) {
			File inputFile = inputFile = new File(input);

			if (inputFile.exists())
				inputFile.delete();

			inputFile.createNewFile();
			firstExecute = true;
			output = new PrintWriter(new FileOutputStream(inputFile, true));
			
			// Print the header in the HTML file 
			output.println(header());
		}

	}

	// This method print the output of the different sources in the HTML file
	public static void print(String line) throws IOException, URISyntaxException {

		output.println(line);

	}

	// This method launches the Web brower with HTML file and display the Analysis and the result
	public static void browse() throws URISyntaxException, IOException {

		output.println(footer());
		output.close();
		File htmlFile = new File(input);

		Desktop.getDesktop().browse(htmlFile.toURI());
		// browse(input);

		if (Desktop.isDesktopSupported()) {
			Desktop desktop = Desktop.getDesktop();
			try {
				desktop.browse(new URI(input));
			} catch (IOException e) {
				e.printStackTrace();
			}
		} else {
			Runtime runtime = Runtime.getRuntime();
			try {
				runtime.exec("xdg-open " + input);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	// Header of the HTML file 
	public static String header() {
		String header = "<!DOCTYPE html>" + "\n" + "<html>" + "\n" + "<head><title>Login</title></head>" + "\n"
				+ "<body>" + "\n" + "<header>" + "\n"
				+ "<h1 style=\"color:blue;background-color:lightgrey;font-family:Verdana;font-style:italic\">Security Analysis</h1>"
				+ "\n" + "</header>";
		return header;

	}

	// Footer of the HTML file
	public static String footer() {
		String footer = "<footer style=\"background-color:lightgrey;font-size:15pt;text-align:center;\">" + "\n"
				+ "Swati Mittal" + "\n" + "<a href=\"https://www.linkedin.com/in/swatisjsu\">  LinkedIn  </a>" + "\n"
				+ "</footer>" + "\n" + "</body>" + "\n" + "</html>";
		return footer;

	}
}
