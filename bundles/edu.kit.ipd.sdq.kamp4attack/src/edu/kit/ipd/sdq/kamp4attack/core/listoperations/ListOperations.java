package edu.kit.ipd.sdq.kamp4attack.core.listoperations;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * This class is responsible for the list operations related to access control
 * 
 * @author Patrick Spiesberger
 * @version 1.0
 *
 */
public class ListOperations {

	private int runningTimes; 
	private boolean returnedAllElements = false;
	private int timeLimits[] = {0, 0, 0, 12, 0, 0 }; // {years, months, days, hours, minutes, seconds}
	private final int defaultTimeLimits[] = {0, 0, 0, 12, 0, 0 };
	
	/**
	 * Constructor of ListOperations
	 */
	public ListOperations() {
		runningTimes = 1;
	}

	
	/**
	 * Generates a list of all lists of a certain length
	 * @param data : list to be subdivided
	 * @param len : desired length of the sublists
	 * @return List of partial lists with length len
	 */
	private List<List<Object>> getCombinationsOfN(List<Object> data, int len) {
		//if (data.size() == 0 || len == 0) {
		if (len == 0) {
			System.out.println("Hier");
			return Collections.emptyList();
		}

		List<List<Object>> combinations = new ArrayList<List<Object>>();
		List<Object> element = new ArrayList<Object>(data);
		element.remove(data.iterator().next());

		List<List<Object>> subSet = getCombinationsOfN(element, len - 1);

		for (List<Object> elem : subSet) {
			List<Object> newElement = new ArrayList<Object>(elem);
			newElement.add(0, data.iterator().next());
		}

		combinations.addAll(getCombinationsOfN(element, len));

		return combinations;
	}

	/**
	 * Generates a list of all sublists
	 * @param data : list to be subdivided
	 * @return : list of partial length
	 */
	private List<List<Object>> getCombinationsAll(List<Object> data) {
		List<List<Object>> combinations = new ArrayList<List<Object>>();
		for (int i = 0; i < Math.pow(2, data.size()); i++) {
			List<Object> element = new ArrayList<Object>();
			for (int elem = 0; elem < data.size(); elem++) {
				if ((i & (int) Math.pow(2, elem)) > 0) {
					element.add(data.get(elem));
				}
			}
			combinations.add(element);
		}
		return combinations;
	}

	/**
	 * Calculates the number of combinations. This number is multiplied by an
	 * estimated duration (see property files) of an individual analysis, 
	 * which results in the approximate total runtime
	 * @param elementSize : number of elements in a list
	 * @param timePerElement : runtime of an analysis in seconds
	 * @return : estimated runtime [years, months, days, hours, minutes, seconds]
	 */
	public int[] calculateTime(int elementSize, int timePerElement) {
		int options = (int) Math.pow(2, elementSize);
		int timePerOption = options * timePerElement;
		int time[] = new int[6];
		time[0] = timePerOption / 31536000; // years
		time[1] = (timePerOption % 31536000) / 2628000; // months
		time[2] = (timePerOption % 2628000) / 86400; // days
		time[3] = (timePerOption % 86400) / 3600; // hours
		time[4] = (timePerOption % 3600) / 60; // minutes
		time[5] = (timePerOption % 60); // seconds
		return time;
	}

	/**
	 * Returns a specific item from a selected list
	 * @param elements : list of elements
	 * @param partList : number of sublist 
	 * @param elementAt : position of element in sublist
	 * @return : specific element
	 */
	public Object getElement(List<List<Object>> elements, int partList, int elementAt) {
		return elements.get(partList).get(elementAt);
	}
	
	/**
	 * Sets the maximum time limit, which is required for the selection of the algorithms
	 * @param timelimit : array [years, months, days, hours, minutes, seconds]
	 */
	public void setTimeLimit(int[] timelimit) {
		if (timelimit.length == 6) {
			timeLimits = timelimit;
		} else {
			java.lang.System.out.println("invalid input of time limit in property file");
			timeLimits = defaultTimeLimits;
		}
	}

	/**
	 * Decide which algorithm is used to select the partial lists (improvement of the runtime)
	 * @param elements : list of elements
	 * @return : List of sublists
	 */
	public List<List<Object>> calculateLists(List<Object> elements) {
		for (int i = 0; i < timeLimits.length; i++) {
			if (calculateTime(elements.size(), 1)[i] > timeLimits[i]) {
				if (runningTimes >= elements.size()) {
					returnedAllElements = true;
					return Collections.emptyList();
				}
				else {
					System.out.println("Test");
					runningTimes++;
					returnedAllElements = false;
					return getCombinationsOfN(elements, elements.size() - runningTimes);
				}
			} else if (timeLimits[i] != 0) {
				break;
			}
		}
		returnedAllElements = true;
		return getCombinationsAll(elements);
	}
	
	/**
	 * Returns whether all sublists are returned.
	 * True = all parts lists were returned
	 * False = a selection of partial lists was returned
	 * A re-execution will return new sublists
	 * @return : status of return values
	 */
	public Boolean getStatus() {
		return returnedAllElements;
	}

}
