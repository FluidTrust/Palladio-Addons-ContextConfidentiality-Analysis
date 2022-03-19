package edu.kit.ipd.sdq.kamp4attack.tests.mitigation.extension.casestudies.travelplanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.junit.jupiter.api.Test;

public class EncryptionWithKeyAtStart extends MitigationTravelPlanner {

	public EncryptionWithKeyAtStart() {
		this.PATH_ATTACKER = "mitigationModels/compositeTravelPlanner/tests/04/test_model.attacker";
		this.PATH_CONTEXT = "mitigationModels/compositeTravelPlanner/tests/04/test_model.context";
		this.PATH_MODIFICATION = "mitigationModels/compositeTravelPlanner/tests/04/test_model.kamp4attackmodificationmarks";
	}

	@Test
	void propagation() {
		runAnalysis();

		var change = getCredentials();

		assertEquals(1, change.getCompromisedassembly().size());
		assertEquals(1, change.getContextchange().size());
		assertEquals(5, change.getCompromiseddata().size()); //3 without hasKey attribute

		assertTrue(checkAssembly(change));

	}

	@Override
	protected boolean assemblyNameMatch(String name) {
		var set = Set.of("Assembly_TravelAgency");
		return set.contains(name);
	}
}
