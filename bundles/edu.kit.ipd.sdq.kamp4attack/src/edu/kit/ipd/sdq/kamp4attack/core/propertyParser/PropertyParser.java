package edu.kit.ipd.sdq.kamp4attack.core.propertyParser;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * This class is responsible for reading out and handling property files
 * 
 * @author Patrick Spiesberger
 * @version 1.0
 *
 */
public class PropertyParser {

	// encryption
	private boolean encrypted = false;
	private Effort crackableEffort = Effort.SECURE;

	// context selection
	private boolean missingAttributesEnabled = true;

	// general
	private int[] timeLimit = new int[6];

	private InputStream input;

	private boolean validInput = true;

	Properties prop = new Properties();

	public PropertyParser(String path) {
		try {
			this.input = new FileInputStream(path);
			try {
				prop.load(input);
				loadValues();
			} catch (IOException e) {
				validInput = false;
				e.printStackTrace();
			}
		} catch (FileNotFoundException e) {
			validInput = false;
			e.printStackTrace();
		}
	}
	

	private void loadValues() {
		//TODO REGEX: check user input
		this.encrypted = Boolean.valueOf(prop.getProperty("encrypted"));
		this.crackableEffort = Effort.valueOf(prop.getProperty("crackableEffort"));
		
		this.missingAttributesEnabled = Boolean.valueOf(prop.getProperty("missingAttributesEnabled"));
		
		String[] separatedStrings = prop.getProperty("timeLimit").replaceAll("\\[", "").replaceAll("]", "").split(",");
		for (int i = 0; i < separatedStrings.length; i++) {
            
            try {
                this.timeLimit[i] = Integer.parseInt(separatedStrings[i]);
            } catch (Exception e) {
                java.lang.System.out.println("Unable to parse string to int: " + e.getMessage());
            }
        }
	}
	
	public boolean isEncrypted() {
		return encrypted;
	}

	public Effort getCrackableEffort() {
		return crackableEffort;
	}

	public boolean isMissingAttributesEnabled() {
		return missingAttributesEnabled;
	}

	public int[] getTimeLimit() {
		return timeLimit;
	}
}

enum Effort {
	SECURE, LOW, MEDIUM, HIGH;
}