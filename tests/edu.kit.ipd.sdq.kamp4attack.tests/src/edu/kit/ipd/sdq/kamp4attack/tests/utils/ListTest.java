package edu.kit.ipd.sdq.kamp4attack.tests.utils;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import edu.kit.ipd.sdq.kamp4attack.core.listoperations.ListOperations;

class ListTest {

	private ListOperations operation;

	@BeforeEach
	void setUP() {
		operation = new ListOperations();
	}

	@Test
	void testGetThreeComb() {
		LinkedList<Object> list = new LinkedList<>();
		list.add(1);
		list.add(2);
		list.add(3);
		assertTrue(operation.calculateLists(list).toString()
				.equals("[[], [1], [2], [1, 2], [3], [1, 3], [2, 3], [1, 2, 3]]"));
	}

	@Test
	void testGetTwentyComb() {
		LinkedList<Object> list = new LinkedList<>();
		for (int i = 1; i <= 20; i++) {
			list.add(i);
		}
		operation.calculateLists(list);
		List<List<Object>> result = operation.calculateLists(list);
		assertTrue(result.size() == 190); // nCr

	}

	@Test
	void calculateTimeSmall() {
		int[] testArray = operation.calculateTime(5, 1);
		int[] checkArray = { 0, 0, 0, 0, 0, 32 };
		assertTrue(Arrays.equals(testArray, checkArray));
	}

	@Test
	void calculateTimeBig() {
		int[] testArray = operation.calculateTime(20, 1);
		int[] checkArray = { 0, 0, 12, 3, 16, 16 };
		assertTrue(Arrays.equals(testArray, checkArray));
	}

	@Test
	void calculateTimeMult() {
		int[] testArray = operation.calculateTime(10, 3);
		int[] checkArray = { 0, 0, 0, 0, 51, 12 };
		assertTrue(Arrays.equals(testArray, checkArray));
	}

	@Test
	void otherObjects() {
		LinkedList<Object> list = new LinkedList<>();
		list.add("Palladio");
		list.add("Komponenten");
		list.add("Modell");
		assertTrue(operation.calculateLists(list).toString().equals(
				"[[], [Palladio], [Komponenten], [Palladio, Komponenten], [Modell], [Palladio, Modell], [Komponenten, Modell], [Palladio, Komponenten, Modell]]"));
	}

	@Test
	void otherObjectsBigInput() {
		LinkedList<Object> list = new LinkedList<>();
		list.add("Palladio");
		list.add("Komponenten");
		list.add("KIT");
		list.add("Informatik");
		list.add("SDQ");
		list.add("KASTEL");
		list.add("Bachelor");
		list.add("Master");
		list.add(1);
		list.add(2);
		list.add(3);
		list.add(4);
		list.add(5);
		list.add(6);
		list.add(7);
		list.add(8);
		list.add(9);
		List<List<Object>> runOne = operation.calculateLists(list);
		List<List<Object>> runTwo = operation.calculateLists(list);
		List<List<Object>> runThree = operation.calculateLists(list);
		List<List<Object>> runFour = operation.calculateLists(list);
		boolean test1 = runOne.size() == 17 && runOne.get(0).size() == 1;
		boolean test2 = runTwo.size() == 136 && runTwo.get(0).size() == 2; 
		boolean test3 = runThree.size() == 680 && runThree.get(0).size() == 3; 
		boolean test4 = runFour.size() == 2380 && runFour.get(0).size() == 4; 
		assertTrue(test1 && test2 && test3 && test4);
	}

}
