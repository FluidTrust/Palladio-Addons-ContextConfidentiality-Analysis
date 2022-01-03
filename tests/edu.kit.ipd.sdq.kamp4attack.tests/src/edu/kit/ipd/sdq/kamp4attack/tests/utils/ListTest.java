package edu.kit.ipd.sdq.kamp4attack.tests.utils;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.LinkedList;

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
		System.out.println(operation.calculateLists(list));	
	}
	
	@Test
	void testGetTwentyComb() {
		LinkedList<Object> list = new LinkedList<>();
		for (int i = 1; i <= 21; i++) {
			list.add(i);
		}
		System.out.println(operation.calculateLists(list));	
		System.out.println(operation.calculateLists(list));	
		System.out.println(operation.calculateLists(list));	
		System.out.println(operation.calculateLists(list));	
		System.out.println(operation.calculateLists(list));	
		System.out.println(operation.calculateLists(list));	
	}
	
	@Test
	void calculateTimeSmall() {
		int[] testArray = operation.calculateTime(5, 1);
		int[] checkArray = {0,0,0,0,0,32};
		assertTrue(Arrays.equals(testArray, checkArray));
	}
	
	@Test
	void calculateTimeBig() {
		int[] testArray = operation.calculateTime(20, 1);
		int[] checkArray = {0,0,12,3,16,16};
		assertTrue(Arrays.equals(testArray, checkArray));
	}
	
	@Test
	void calculateTimeMult() {
		int[] testArray = operation.calculateTime(10, 3);
		int[] checkArray = {0,0,0,0,51,12};
		assertTrue(Arrays.equals(testArray, checkArray));
	}


}
