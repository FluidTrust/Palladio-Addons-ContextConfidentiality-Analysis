package edu.kit.ipd.sdq.kamp4attack.tests.utils;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.ListOperationEffort;
import org.palladiosimulator.pcm.confidentiality.context.system.SystemFactory;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;

import edu.kit.ipd.sdq.kamp4attack.core.contextSelection.ListOperations;

class ListTest {

	private ListOperations operation;

	private List<UsageSpecification> createSpecification(int length) {
		List<UsageSpecification> usages = new LinkedList<>();
		for (int i = 0; i < length; i++) {
			UsageSpecification usage = SystemFactory.eINSTANCE.createUsageSpecification();
			usage.setId(String.valueOf(i));
			usage.setEntityName(String.valueOf(i));
			usages.add(usage);
		}
		return usages;
	}

	@BeforeEach
	void setUP() {
		operation = new ListOperations();
	}

	@Test
	void testGetThreeComb() {
		LinkedList<Integer> list = new LinkedList<>();
		list.add(1);
		list.add(2);
		list.add(3);
		assertTrue(operation.getCombinationsAllTest(list).toString()
				.equals("[[1, 2, 3], [2, 3], [1, 3], [3], [1, 2], [2], [1], []]"));
	}

	@Test
	void testGetTwentyComb() {
		Attacker attacker = AttackerFactory.eINSTANCE.createAttacker();
		attacker.setContextSelectionListEffort(ListOperationEffort.PART);
		List<UsageSpecification> usages = createSpecification(20);
		operation.calculateLists(usages, attacker); //20 nCr 20
		operation.calculateLists(usages, attacker); //empty List
		operation.calculateLists(usages, attacker); //20 nCr 19
		operation.calculateLists(usages, attacker); //20 nCr 1
		List<List<UsageSpecification>> result = operation.calculateLists(usages, attacker);
		assertTrue(result.size() == 190); // 20 nCr 18
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
	void otherUsageSpecifications() {
		List<UsageSpecification> usages = createSpecification(3);
		List<List<UsageSpecification>> calculatedList = operation.calculateLists(usages, null);
		assertEquals(3, calculatedList.get(0).size());
		assertEquals(2, calculatedList.get(1).size());
		assertEquals(2, calculatedList.get(2).size());
		assertEquals(1, calculatedList.get(3).size());
	}

	@Test
	void otherUsageSpecificationsBigInput() {
		Attacker attacker = AttackerFactory.eINSTANCE.createAttacker();
		attacker.setContextSelectionListEffort(ListOperationEffort.PART);
		List<UsageSpecification> usages = createSpecification(50);
		for (int i = 0; i < 10; i++) {
			operation.calculateLists(usages, attacker);
		} // 50 nCr 4
		assertEquals(2118760, operation.calculateLists(usages, attacker).size()); //50 nCr 45
	}

}