package edu.kit.ipd.sdq.kamp4attack.core.listoperations;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * util-class for list operations, used for attribute based control system
 * 
 * @author Patrick Spiesberger
 *
 */
public class ListOperations {

	private List<Object> list;
	private int runningTimes;

	private final int timeLimits[] = { 0, 0, 0, 12, 0, 0, 0 }; // {years, months, days, hours, minutes, seconds}

	public ListOperations(List<Object> list) {
		this.list = list;
		runningTimes = 0;
	}

	private List<List<Object>> getCombinationsOfN(List<Object> data, int len) {
		if (data.size() == 0 || len == 0) {
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

	private int[] calculateTime(int elementSize, int timePerElement) {
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

	public Object getElement(List<List<Object>> elements, int partList, int elementAt) {
		return elements.get(partList).get(elementAt);
	}

	public List<List<Object>> calculateLists(List<Object> elements) {
		for (int i = 0; i < timeLimits.length; i++) {
			if (calculateTime(elements.size(), 1)[i] > timeLimits[i]) {
				if (runningTimes >= elements.size()) {
					return Collections.emptyList();
				}
				else {
					runningTimes++;
					return getCombinationsOfN(elements, runningTimes);
				}
			}
		}
		return getCombinationsAll(elements);
	}

}
