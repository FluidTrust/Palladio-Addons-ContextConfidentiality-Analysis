package edu.kit.ipd.sdq.kamp4attack.tests.mitigation.extension.casestudies.travelplanner;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class PreventionTest extends MitigationTravelPlanner {

	public PreventionTest() {
		this.PATH_ATTACKER = "mitigationModels/compositeTravelPlanner/tests/07/test_model.attacker";
		this.PATH_CONTEXT = "mitigationModels/compositeTravelPlanner/tests/07/test_model.context";
		this.PATH_MODIFICATION = "mitigationModels/compositeTravelPlanner/tests/07/test_model.kamp4attackmodificationmarks";
	}

	/**
	 * In this test, propagation is not constrained, so 11 items are examined. Then,
	 * with the help of Prevention 2 elements are blocked
	 */
	@Test
	void propagation() {
		runAnalysis();

		var change = getCredentials();

		assertEquals(9, change.getCompromisedassembly().size());
		assertEquals(17, change.getCompromiseddata().size());
	}
}
