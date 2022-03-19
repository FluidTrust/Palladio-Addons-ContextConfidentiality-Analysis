package edu.kit.ipd.sdq.kamp4attack.tests.mitigation.extension.casestudies.travelplanner;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class SimpleEncryptionWithNoCredentials extends MitigationTravelPlanner {

	public SimpleEncryptionWithNoCredentials() {
		this.PATH_ATTACKER = "mitigationModels/compositeTravelPlanner/tests/03/test_model.attacker";
		this.PATH_CONTEXT = "mitigationModels/compositeTravelPlanner/tests/03/test_model.context";
		this.PATH_MODIFICATION = "mitigationModels/compositeTravelPlanner/tests/03/test_model.kamp4attackmodificationmarks";
	}

	@Test
	void propagation() {
		runAnalysis();

		var change = getCredentials();

		assertEquals(11, change.getCompromisedassembly().size());
		assertEquals(6, change.getCompromiseddata().size()); //17 without mitigation
	}
}
