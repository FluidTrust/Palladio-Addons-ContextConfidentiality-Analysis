package edu.kit.ipd.sdq.kamp4attack.tests.mitigation.extension.effort;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import edu.kit.ipd.sdq.kamp4attack.core.AttackPropagationAnalysis;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.tests.AbstractModelTest;

class VulnerableListEffortTwentyTest extends AbstractModelTest {

	public VulnerableListEffortTwentyTest() {
		this.PATH_ATTACKER = "contextSelectionModels/effortModels/vulnerableEffortModel/attacker/twentyAttribute.attacker";
		this.PATH_ASSEMBLY = "contextSelectionModels/effortModels/vulnerableEffortModel/simpleEffort.system";
		this.PATH_ALLOCATION = "contextSelectionModels/effortModels/vulnerableEffortModel/simpleEffort.allocation";
		this.PATH_CONTEXT = "contextSelectionModels/effortModels/vulnerableEffortModel/effort.context";
		this.PATH_MODIFICATION = "contextSelectionModels/effortModels/vulnerableEffortModel/modificationmarks/twenty.kamp4attackmodificationmarks";
		this.PATH_REPOSITORY = "contextSelectionModels/effortModels/vulnerableEffortModel/simpleEffort.repository";
		this.PATH_USAGE = "contextSelectionModels/effortModels/vulnerableEffortModel/simpleEffort.usagemodel";
		this.PATH_RESOURCES = "contextSelectionModels/effortModels/vulnerableEffortModel/simpleEffort.resourceenvironment";
	}

	@BeforeEach
	protected void execute() {
		generateXML();
		final var wrapper = getBlackboardWrapper();
		(new AttackPropagationAnalysis()).runChangePropagationAnalysis(wrapper);
	}

	@Test
	void testVulnerableCaseTwentyAttribute() {
		final var steps = this.modification.getChangePropagationSteps();
		assertEquals(1, steps.size());
		assertEquals(2, ((CredentialChange) steps.get(0)).getCompromisedassembly().size());
	}
}
